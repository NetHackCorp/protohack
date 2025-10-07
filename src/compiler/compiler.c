#include "protohack/compiler.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "protohack/chunk.h"
#include "protohack/config.h"
#include "protohack/error.h"
#include "protohack/function.h"
#include "protohack/internal/common.h"
#include "protohack/native.h"
#include "protohack/opcode.h"
#include "protohack/types.h"
#include "protohack/value.h"

typedef enum {
    TOKEN_LEFT_PAREN,
    TOKEN_RIGHT_PAREN,
    TOKEN_LEFT_BRACE,
    TOKEN_RIGHT_BRACE,
    TOKEN_LEFT_BRACKET,
    TOKEN_RIGHT_BRACKET,
    TOKEN_COMMA,
    TOKEN_DOT,
    TOKEN_PIPE,
    TOKEN_COLON,
    TOKEN_MINUS,
    TOKEN_PLUS,
    TOKEN_SEMICOLON,
    TOKEN_SLASH,
    TOKEN_STAR,
    TOKEN_BANG,
    TOKEN_BANG_EQUAL,
    TOKEN_EQUAL,
    TOKEN_EQUAL_EQUAL,
    TOKEN_GREATER,
    TOKEN_GREATER_EQUAL,
    TOKEN_LESS,
    TOKEN_LESS_EQUAL,
    TOKEN_IDENTIFIER,
    TOKEN_STRING,
    TOKEN_NUMBER,
    TOKEN_AND,
    TOKEN_OR,
    TOKEN_ELSE,
    TOKEN_FALSE,
    TOKEN_FOR,
    TOKEN_IF,
    TOKEN_LET,
    TOKEN_NULL,
    TOKEN_PRINT,
    TOKEN_TRUE,
    TOKEN_WHILE,
    TOKEN_CONST,
    TOKEN_CRAFT,
    TOKEN_CALL,
    TOKEN_GIVES,
    TOKEN_YIELD,
    TOKEN_FLAG,
    TOKEN_NUMERIC,
    TOKEN_TEXT,
    TOKEN_RAW,
    TOKEN_NONE,
    TOKEN_AS,
    TOKEN_CARVE,
    TOKEN_ETCH,
    TOKEN_PROBE,
    TOKEN_EOF,
    TOKEN_ERROR
} TokenType;

typedef struct {
    TokenType type;
    const char *start;
    size_t length;
    size_t line;
} Token;

typedef struct {
    const char *start;
    const char *current;
    size_t line;
} Scanner;

static void scanner_init(Scanner *scanner, const char *source) {
    scanner->start = source;
    scanner->current = source;
    scanner->line = 1;
}

static bool scanner_is_at_end(const Scanner *scanner) {
    return *scanner->current == '\0';
}

static char scanner_advance(Scanner *scanner) {
    scanner->current++;
    return scanner->current[-1];
}

static char scanner_peek(const Scanner *scanner) {
    return *scanner->current;
}

static char scanner_peek_next(const Scanner *scanner) {
    if (scanner_is_at_end(scanner)) {
        return '\0';
    }
    return scanner->current[1];
}

static bool scanner_match(Scanner *scanner, char expected) {
    if (scanner_is_at_end(scanner)) {
        return false;
    }
    if (*scanner->current != expected) {
        return false;
    }
    scanner->current++;
    return true;
}

static void scanner_skip_whitespace(Scanner *scanner) {
    for (;;) {
        char c = scanner_peek(scanner);
        switch (c) {
            case ' ':
            case '\r':
            case '\t':
                scanner_advance(scanner);
                break;
            case '\n':
                scanner->line++;
                scanner_advance(scanner);
                break;
            case '/':
                if (scanner_peek_next(scanner) == '/') {
                    while (scanner_peek(scanner) != '\n' && !scanner_is_at_end(scanner)) {
                        scanner_advance(scanner);
                    }
                } else {
                    return;
                }
                break;
            default:
                return;
        }
    }
}

static Token scanner_make_token(Scanner *scanner, TokenType type) {
    Token token;
    token.type = type;
    token.start = scanner->start;
    token.length = (size_t)(scanner->current - scanner->start);
    token.line = scanner->line;
    return token;
}

static Token scanner_error_token(Scanner *scanner, const char *message) {
    Token token;
    token.type = TOKEN_ERROR;
    token.start = message;
    token.length = strlen(message);
    token.line = scanner->line;
    return token;
}

static bool scanner_is_alpha(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static bool scanner_is_digit(char c) {
    return c >= '0' && c <= '9';
}

static TokenType scanner_identifier_type(const Token *token) {
    switch (token->start[0]) {
        case 'a':
            if (token->length == 3 && memcmp(token->start, "and", 3) == 0) {
                return TOKEN_AND;
            }
            if (token->length == 2 && memcmp(token->start, "as", 2) == 0) {
                return TOKEN_AS;
            }
            break;
        case 'c':
            if (token->length == 5 && memcmp(token->start, "const", 5) == 0) {
                return TOKEN_CONST;
            }
            if (token->length == 5 && memcmp(token->start, "craft", 5) == 0) {
                return TOKEN_CRAFT;
            }
            if (token->length == 4 && memcmp(token->start, "call", 4) == 0) {
                return TOKEN_CALL;
            }
            if (token->length == 5 && memcmp(token->start, "carve", 5) == 0) {
                return TOKEN_CARVE;
            }
            break;
        case 'e':
            if (token->length == 4 && memcmp(token->start, "else", 4) == 0) {
                return TOKEN_ELSE;
            }
            if (token->length == 4 && memcmp(token->start, "etch", 4) == 0) {
                return TOKEN_ETCH;
            }
            break;
        case 'f':
            if (token->length == 5 && memcmp(token->start, "false", 5) == 0) {
                return TOKEN_FALSE;
            }
            if (token->length == 3 && memcmp(token->start, "for", 3) == 0) {
                return TOKEN_FOR;
            }
            if (token->length == 4 && memcmp(token->start, "flag", 4) == 0) {
                return TOKEN_FLAG;
            }
            break;
        case 'i':
            if (token->length == 2 && memcmp(token->start, "if", 2) == 0) {
                return TOKEN_IF;
            }
            break;
        case 'l':
            if (token->length == 3 && memcmp(token->start, "let", 3) == 0) {
                return TOKEN_LET;
            }
            break;
        case 'n':
            if (token->length == 4 && memcmp(token->start, "null", 4) == 0) {
                return TOKEN_NULL;
            }
            if ((token->length == 3 && memcmp(token->start, "num", 3) == 0) ||
                (token->length == 7 && memcmp(token->start, "numeric", 7) == 0)) {
                return TOKEN_NUMERIC;
            }
            if (token->length == 4 && memcmp(token->start, "none", 4) == 0) {
                return TOKEN_NONE;
            }
            break;
        case 'o':
            if (token->length == 2 && memcmp(token->start, "or", 2) == 0) {
                return TOKEN_OR;
            }
            break;
        case 'p':
            if (token->length == 5 && memcmp(token->start, "print", 5) == 0) {
                return TOKEN_PRINT;
            }
            if (token->length == 5 && memcmp(token->start, "probe", 5) == 0) {
                return TOKEN_PROBE;
            }
            break;
        case 't':
            if (token->length == 4 && memcmp(token->start, "true", 4) == 0) {
                return TOKEN_TRUE;
            }
            if (token->length == 4 && memcmp(token->start, "text", 4) == 0) {
                return TOKEN_TEXT;
            }
            break;
        case 'w':
            if (token->length == 5 && memcmp(token->start, "while", 5) == 0) {
                return TOKEN_WHILE;
            }
            break;
        case 'r':
            if (token->length == 3 && memcmp(token->start, "raw", 3) == 0) {
                return TOKEN_RAW;
            }
            break;
        case 'g':
            if (token->length == 5 && memcmp(token->start, "gives", 5) == 0) {
                return TOKEN_GIVES;
            }
            break;
        case 'y':
            if (token->length == 5 && memcmp(token->start, "yield", 5) == 0) {
                return TOKEN_YIELD;
            }
            break;
        default:
            break;
    }
    return TOKEN_IDENTIFIER;
}

static Token scanner_identifier(Scanner *scanner) {
    while (scanner_is_alpha(scanner_peek(scanner)) || scanner_is_digit(scanner_peek(scanner))) {
        scanner_advance(scanner);
    }
    Token token = scanner_make_token(scanner, TOKEN_IDENTIFIER);
    token.type = scanner_identifier_type(&token);
    return token;
}

static Token scanner_number(Scanner *scanner) {
    while (scanner_is_digit(scanner_peek(scanner))) {
        scanner_advance(scanner);
    }
    if (scanner_peek(scanner) == '.' && scanner_is_digit(scanner_peek_next(scanner))) {
        scanner_advance(scanner);
        while (scanner_is_digit(scanner_peek(scanner))) {
            scanner_advance(scanner);
        }
    }
    return scanner_make_token(scanner, TOKEN_NUMBER);
}

static Token scanner_string(Scanner *scanner) {
    while (scanner_peek(scanner) != '"' && !scanner_is_at_end(scanner)) {
        if (scanner_peek(scanner) == '\n') {
            scanner->line++;
        }
        scanner_advance(scanner);
    }
    if (scanner_is_at_end(scanner)) {
        return scanner_error_token(scanner, "Unterminated string literal");
    }
    scanner_advance(scanner);
    return scanner_make_token(scanner, TOKEN_STRING);
}

static Token scanner_scan_token(Scanner *scanner) {
    scanner_skip_whitespace(scanner);
    scanner->start = scanner->current;

    if (scanner_is_at_end(scanner)) {
        return scanner_make_token(scanner, TOKEN_EOF);
    }

    char c = scanner_advance(scanner);

    if (scanner_is_alpha(c)) {
        return scanner_identifier(scanner);
    }
    if (scanner_is_digit(c)) {
        return scanner_number(scanner);
    }

    switch (c) {
        case '(': return scanner_make_token(scanner, TOKEN_LEFT_PAREN);
        case ')': return scanner_make_token(scanner, TOKEN_RIGHT_PAREN);
        case '{': return scanner_make_token(scanner, TOKEN_LEFT_BRACE);
        case '}': return scanner_make_token(scanner, TOKEN_RIGHT_BRACE);
    case '[': return scanner_make_token(scanner, TOKEN_LEFT_BRACKET);
    case ']': return scanner_make_token(scanner, TOKEN_RIGHT_BRACKET);
        case ';': return scanner_make_token(scanner, TOKEN_SEMICOLON);
        case ',': return scanner_make_token(scanner, TOKEN_COMMA);
        case '.': return scanner_make_token(scanner, TOKEN_DOT);
        case '-': return scanner_make_token(scanner, TOKEN_MINUS);
        case '+': return scanner_make_token(scanner, TOKEN_PLUS);
    case '|': return scanner_make_token(scanner, TOKEN_PIPE);
    case ':': return scanner_make_token(scanner, TOKEN_COLON);
        case '/': return scanner_make_token(scanner, TOKEN_SLASH);
        case '*': return scanner_make_token(scanner, TOKEN_STAR);
        case '!': return scanner_make_token(scanner, scanner_match(scanner, '=') ? TOKEN_BANG_EQUAL : TOKEN_BANG);
        case '=': return scanner_make_token(scanner, scanner_match(scanner, '=') ? TOKEN_EQUAL_EQUAL : TOKEN_EQUAL);
        case '<': return scanner_make_token(scanner, scanner_match(scanner, '=') ? TOKEN_LESS_EQUAL : TOKEN_LESS);
        case '>': return scanner_make_token(scanner, scanner_match(scanner, '=') ? TOKEN_GREATER_EQUAL : TOKEN_GREATER);
        case '"': return scanner_string(scanner);
        default:
            break;
    }

    return scanner_error_token(scanner, "Unexpected character");
}

typedef enum {
    PREC_NONE,
    PREC_ASSIGNMENT,
    PREC_OR,
    PREC_AND,
    PREC_EQUALITY,
    PREC_COMPARISON,
    PREC_TERM,
    PREC_FACTOR,
    PREC_UNARY,
    PREC_PRIMARY
} Precedence;

struct Parser;

typedef void (*ParseFn)(struct Parser *parser, bool can_assign);

typedef struct {
    ParseFn prefix;
    ParseFn infix;
    Precedence precedence;
} ParseRule;

typedef struct Local {
    Token name;
    uint8_t depth;
    bool is_const;
    ProtoTypeTag type_tag;
} Local;

typedef struct CompilerContext {
    ProtoFunction *function;
    ProtoChunk *chunk;
    Local locals[PROTOHACK_MAX_LOCALS];
    int local_count;
    int scope_depth;
    ProtoTypeTag expected_return;
    struct CompilerContext *enclosing;
} CompilerContext;

typedef struct Parser {
    Scanner scanner;
    Token current;
    Token previous;
    bool had_error;
    bool panic_mode;
    ProtoChunk *chunk;
    ProtoError *error;
    struct {
        bool defined[PROTOHACK_MAX_GLOBALS];
        bool is_const[PROTOHACK_MAX_GLOBALS];
    } globals;
    int initializing_global;
    CompilerContext *compiler;
    CompilerContext root;
} Parser;

static void parser_advance(Parser *parser);
static void parse_expression(Parser *parser);
static void declaration(Parser *parser);
static ParseRule *get_rule(TokenType type);
static void parse_precedence(Parser *parser, Precedence precedence);
static void statement(Parser *parser);
static void let_declaration(Parser *parser, bool is_const);
static CompilerContext *current_context(Parser *parser);
static void begin_scope(Parser *parser);
static void end_scope(Parser *parser);
static void add_local(Parser *parser, Token name, bool is_const, ProtoTypeTag type_tag);
static int resolve_local(Parser *parser, Token name);
static void mark_initialized(Parser *parser);
static ProtoTypeTag parse_type_tag(Parser *parser);
static ProtoTypeTag require_callable_type(Parser *parser, const char *message);
static void emit_byte(Parser *parser, uint8_t byte);
static uint8_t parse_call_arguments(Parser *parser);
static void compile_named_call(Parser *parser, Token name, int local_slot, bool paren_consumed);
static void parse_call_keyword(Parser *parser, bool can_assign);
static void parse_carve(Parser *parser, bool can_assign);
static void parse_probe(Parser *parser, bool can_assign);
static void craft_declaration(Parser *parser);
static void parse_function_body(Parser *parser, ProtoFunction *function);
static void yield_statement(Parser *parser);
static void etch_statement(Parser *parser);
static void sync_function_globals(Parser *parser, ProtoChunk *chunk);

static void parser_init(Parser *parser, const char *source, ProtoChunk *chunk, ProtoError *error) {
    scanner_init(&parser->scanner, source);
    parser->had_error = false;
    parser->panic_mode = false;
    parser->chunk = chunk;
    parser->error = error;
    memset(parser->globals.defined, 0, sizeof parser->globals.defined);
    memset(parser->globals.is_const, 0, sizeof parser->globals.is_const);
    parser->initializing_global = -1;
    parser->root.function = NULL;
    parser->root.chunk = chunk;
    parser->root.local_count = 0;
    parser->root.scope_depth = 0;
    parser->root.expected_return = PROTO_TYPE_NONE;
    parser->root.enclosing = NULL;
    parser->compiler = &parser->root;
}

static void error_at(Parser *parser, const Token *token, const char *message) {
    if (parser->panic_mode) {
        return;
    }
    parser->panic_mode = true;
    parser->had_error = true;
    if (parser->error && parser->error->ok) {
        protoerror_set(parser->error, token->line, "%s", message);
    }
}

static void error_at_current(Parser *parser, const char *message) {
    error_at(parser, &parser->current, message);
}

static void error(Parser *parser, const char *message) {
    error_at(parser, &parser->previous, message);
}

static void parser_advance(Parser *parser) {
    parser->previous = parser->current;

    for (;;) {
        parser->current = scanner_scan_token(&parser->scanner);
        if (parser->current.type != TOKEN_ERROR) {
            break;
        }
        error_at_current(parser, parser->current.start);
    }
}

static bool check(Parser *parser, TokenType type) {
    return parser->current.type == type;
}

static bool match(Parser *parser, TokenType type) {
    if (!check(parser, type)) {
        return false;
    }
    parser_advance(parser);
    return true;
}

static void consume(Parser *parser, TokenType type, const char *message) {
    if (parser->current.type == type) {
        parser_advance(parser);
        return;
    }
    error_at_current(parser, message);
}

static CompilerContext *current_context(Parser *parser) {
    return parser->compiler ? parser->compiler : &parser->root;
}

static ProtoChunk *current_chunk(Parser *parser) {
    CompilerContext *context = current_context(parser);
    return context && context->chunk ? context->chunk : parser->chunk;
}

static void add_local(Parser *parser, Token name, bool is_const, ProtoTypeTag type_tag) {
    CompilerContext *context = current_context(parser);
    if (!context) {
        return;
    }
    if (context->local_count >= PROTOHACK_MAX_LOCALS) {
        error(parser, "Too many local variables in scope");
        return;
    }
    Local *local = &context->locals[context->local_count++];
    local->name = name;
    local->depth = 255;
    local->is_const = is_const;
    local->type_tag = type_tag;
}

static void begin_scope(Parser *parser) {
    CompilerContext *context = current_context(parser);
    if (context) {
        context->scope_depth++;
    }
}

static void end_scope(Parser *parser) {
    CompilerContext *context = current_context(parser);
    if (!context) {
        return;
    }
    if (context->scope_depth > 0) {
        context->scope_depth--;
    }
    while (context->local_count > 0 && context->locals[context->local_count - 1].depth > context->scope_depth) {
        emit_byte(parser, PROTO_OP_POP);
        context->local_count--;
    }
}

static int resolve_local(Parser *parser, Token name) {
    CompilerContext *context = current_context(parser);
    if (!context) {
        return -1;
    }
    for (int i = context->local_count - 1; i >= 0; --i) {
        Local *local = &context->locals[i];
        if (local->name.length == name.length && memcmp(local->name.start, name.start, name.length) == 0) {
            if (local->depth == 255) {
                error(parser, "Cannot read local variable in its own initializer");
            }
            return i;
        }
    }
    return -1;
}

static void mark_initialized(Parser *parser) {
    CompilerContext *context = current_context(parser);
    if (!context) {
        return;
    }
    if (context->scope_depth == 0) {
        return;
    }
    if (context->local_count > 0) {
        context->locals[context->local_count - 1].depth = (uint8_t)context->scope_depth;
    }
}

static ProtoTypeTag parse_type_tag(Parser *parser) {
    switch (parser->current.type) {
        case TOKEN_NUMERIC:
            parser_advance(parser);
            return PROTO_TYPE_NUM;
        case TOKEN_FLAG:
            parser_advance(parser);
            return PROTO_TYPE_FLAG;
        case TOKEN_TEXT:
            parser_advance(parser);
            return PROTO_TYPE_TEXT;
        case TOKEN_RAW:
            parser_advance(parser);
            return PROTO_TYPE_RAW;
        case TOKEN_NONE:
            parser_advance(parser);
            return PROTO_TYPE_NONE;
        default:
            error_at_current(parser, "Expect type specifier");
            return PROTO_TYPE_ANY;
    }
}

static void emit_byte(Parser *parser, uint8_t byte) {
    protochunk_write(current_chunk(parser), byte, parser->previous.line);
}

static void emit_return(Parser *parser) {
    protochunk_write(current_chunk(parser), PROTO_OP_NULL, parser->previous.line);
    protochunk_write(current_chunk(parser), PROTO_OP_RETURN, parser->previous.line);
}

static uint16_t make_constant(Parser *parser, ProtoValue value) {
    size_t index = protochunk_add_constant(current_chunk(parser), value);
    if (index > 65535u) {
        error(parser, "Too many constants in chunk");
        return 0;
    }
    return (uint16_t)index;
}

static void emit_constant(Parser *parser, ProtoValue value) {
    uint16_t index = make_constant(parser, value);
    protochunk_write(current_chunk(parser), PROTO_OP_CONSTANT, parser->previous.line);
    protochunk_write_u16(current_chunk(parser), index, parser->previous.line);
}

static void emit_number_literal(Parser *parser, double value) {
    emit_constant(parser, proto_value_number(value));
}

static void emit_get_global(Parser *parser, const Token *name_token, uint16_t index) {
    protochunk_write(current_chunk(parser), PROTO_OP_GET_GLOBAL, name_token->line);
    protochunk_write_u16(current_chunk(parser), index, name_token->line);
}

static void emit_set_global(Parser *parser, const Token *name_token, uint16_t index) {
    protochunk_write(current_chunk(parser), PROTO_OP_SET_GLOBAL, name_token->line);
    protochunk_write_u16(current_chunk(parser), index, name_token->line);
}

static uint8_t parse_call_arguments(Parser *parser) {
    uint16_t arg_count = 0;
    if (!check(parser, TOKEN_RIGHT_PAREN)) {
        do {
            parse_expression(parser);
            if (arg_count >= UINT8_MAX) {
                error(parser, "Too many arguments");
            } else {
                arg_count++;
            }
        } while (match(parser, TOKEN_COMMA));
    }
    consume(parser, TOKEN_RIGHT_PAREN, "Expect ')' after arguments");
    if (arg_count > UINT8_MAX) {
        return UINT8_MAX;
    }
    return (uint8_t)arg_count;
}

static void emit_get_local(Parser *parser, uint8_t slot, size_t line) {
    protochunk_write(current_chunk(parser), PROTO_OP_GET_LOCAL, line);
    protochunk_write(current_chunk(parser), slot, line);
}

static void emit_set_local(Parser *parser, uint8_t slot, size_t line) {
    protochunk_write(current_chunk(parser), PROTO_OP_SET_LOCAL, line);
    protochunk_write(current_chunk(parser), slot, line);
}

static uint16_t emit_jump(Parser *parser, uint8_t instruction) {
    protochunk_write(current_chunk(parser), instruction, parser->previous.line);
    protochunk_write(current_chunk(parser), 0xFF, parser->previous.line);
    protochunk_write(current_chunk(parser), 0xFF, parser->previous.line);
    return (uint16_t)(current_chunk(parser)->code_count - 2);
}

static void patch_jump(Parser *parser, uint16_t offset) {
    ProtoChunk *chunk = current_chunk(parser);
    size_t jump = chunk->code_count - offset - 2;
    if (jump > 65535u) {
        error(parser, "Jump offset too large");
        return;
    }
    chunk->code[offset] = (uint8_t)((jump >> 8) & 0xFFu);
    chunk->code[offset + 1] = (uint8_t)(jump & 0xFFu);
}

static void emit_loop(Parser *parser, size_t loop_start) {
    ProtoChunk *chunk = current_chunk(parser);
    size_t offset = chunk->code_count - loop_start + 3;
    if (offset > 65535u) {
        error(parser, "Loop body too large");
        return;
    }
    protochunk_write(chunk, PROTO_OP_LOOP, parser->previous.line);
    protochunk_write_u16(chunk, (uint16_t)offset, parser->previous.line);
}

static bool token_to_identifier(const Token *token, char *buffer, size_t buffer_size) {
    if (token->length >= buffer_size) {
        return false;
    }
    memcpy(buffer, token->start, token->length);
    buffer[token->length] = '\0';
    return true;
}

static int declare_global(Parser *parser, Token name, bool is_const) {
    char identifier[PROTOHACK_MAX_IDENTIFIER + 1];
    if (!token_to_identifier(&name, identifier, sizeof identifier)) {
        error(parser, "Identifier is too long");
        return -1;
    }
    ProtoChunk *global_chunk = parser->chunk;
    int existing = protochunk_find_global(global_chunk, identifier);
    if (existing >= 0) {
        if (parser->globals.defined[existing]) {
            error(parser, "Global already defined");
            return -1;
        }
        parser->globals.is_const[existing] = is_const;
        return existing;
    }
    int index = protochunk_intern_global(global_chunk, identifier);
    if (index < 0) {
        error(parser, "Unable to allocate new global");
        return -1;
    }
    parser->globals.defined[index] = false;
    parser->globals.is_const[index] = is_const;
    return index;
}

static int resolve_global(Parser *parser, Token name) {
    char identifier[PROTOHACK_MAX_IDENTIFIER + 1];
    if (!token_to_identifier(&name, identifier, sizeof identifier)) {
        error(parser, "Identifier is too long");
        return -1;
    }
    ProtoChunk *global_chunk = parser->chunk;
    int index = protochunk_find_global(global_chunk, identifier);
    if (index < 0 || !parser->globals.defined[index]) {
        error(parser, "Undefined global");
        return -1;
    }
    return index;
}

static void finish_native_call(Parser *parser, const Token *name_token) {
    char identifier[PROTOHACK_MAX_IDENTIFIER + 1];
    if (!token_to_identifier(name_token, identifier, sizeof identifier)) {
        error(parser, "Identifier is too long");
        return;
    }

    int native_index = protonative_index(identifier);
    if (native_index < 0) {
        error(parser, "Unknown native function");
        return;
    }

    const ProtoNativeEntry *entry = protonative_resolve(identifier);
    if (!entry) {
        error(parser, "Unknown native function");
        return;
    }

    uint8_t arg_count = parse_call_arguments(parser);
    if (arg_count > PROTOHACK_MAX_NATIVE_ARGS) {
        error(parser, "Too many arguments for native call");
        return;
    }
    if (arg_count < entry->min_arity || arg_count > entry->max_arity) {
        error(parser, "Invalid argument count for native function");
        return;
    }

    protochunk_write(current_chunk(parser), PROTO_OP_CALL_NATIVE, name_token->line);
    protochunk_write(current_chunk(parser), (uint8_t)native_index, name_token->line);
    protochunk_write(current_chunk(parser), arg_count, name_token->line);
}

static void compile_named_call(Parser *parser, Token name, int local_slot, bool paren_consumed) {
    if (local_slot >= 0) {
        emit_get_local(parser, (uint8_t)local_slot, name.line);
    } else {
        int global_index = resolve_global(parser, name);
        if (global_index < 0) {
            return;
        }
        emit_get_global(parser, &name, (uint16_t)global_index);
    }
    if (!paren_consumed) {
        parser_advance(parser);
    }
    uint8_t arg_count = parse_call_arguments(parser);
    emit_byte(parser, PROTO_OP_CALL);
    emit_byte(parser, arg_count);
}

static void parse_call_keyword(Parser *parser, bool can_assign) {
    (void)can_assign;
    consume(parser, TOKEN_IDENTIFIER, "Expect function name after 'call'");
    Token name = parser->previous;
    CompilerContext *context = current_context(parser);
    int local_slot = context ? resolve_local(parser, name) : -1;
    consume(parser, TOKEN_LEFT_PAREN, "Expect '(' after function name");
    compile_named_call(parser, name, local_slot, true);
}

static ProtoTypeTag require_callable_type(Parser *parser, const char *message) {
    ProtoTypeTag type_tag = parse_type_tag(parser);
    if (type_tag == PROTO_TYPE_ANY) {
        error(parser, message);
    }
    return type_tag;
}

static void parse_carve(Parser *parser, bool can_assign) {
    (void)can_assign;
    ProtoTypeTag type_tag = require_callable_type(parser, "Expect type before '(' in carve");
    consume(parser, TOKEN_LEFT_PAREN, "Expect '(' after carve type");
    parse_expression(parser);
    consume(parser, TOKEN_RIGHT_PAREN, "Expect ')' after carve count");
    emit_byte(parser, PROTO_OP_ALLOC_TYPED);
    emit_byte(parser, (uint8_t)type_tag);
}

static void parse_probe(Parser *parser, bool can_assign) {
    (void)can_assign;
    ProtoTypeTag type_tag = require_callable_type(parser, "Expect type before '(' in probe");
    consume(parser, TOKEN_LEFT_PAREN, "Expect '(' after probe type");
    parse_expression(parser);
    consume(parser, TOKEN_COMMA, "Expect ',' after memory reference");
    parse_expression(parser);
    consume(parser, TOKEN_RIGHT_PAREN, "Expect ')' after probe arguments");
    emit_byte(parser, PROTO_OP_LOAD_TYPED);
    emit_byte(parser, (uint8_t)type_tag);
}

static void parse_grouping(Parser *parser, bool can_assign) {
    (void)can_assign;
    parse_expression(parser);
    consume(parser, TOKEN_RIGHT_PAREN, "Expect ')' after expression");
}

static void parse_unary(Parser *parser, bool can_assign) {
    (void)can_assign;
    TokenType operator_type = parser->previous.type;
    parse_precedence(parser, PREC_UNARY);

    switch (operator_type) {
        case TOKEN_BANG:
            emit_byte(parser, PROTO_OP_NOT);
            break;
        case TOKEN_MINUS:
            emit_byte(parser, PROTO_OP_NEGATE);
            break;
        default:
            return;
    }
}

static void parse_binary(Parser *parser, bool can_assign) {
    (void)can_assign;
    TokenType operator_type = parser->previous.type;
    ParseRule *rule = get_rule(operator_type);
    Precedence next_precedence = (Precedence)(rule->precedence + 1);
    parse_precedence(parser, next_precedence);

    switch (operator_type) {
        case TOKEN_PLUS:
            emit_byte(parser, PROTO_OP_ADD);
            break;
        case TOKEN_MINUS:
            emit_byte(parser, PROTO_OP_SUB);
            break;
        case TOKEN_STAR:
            emit_byte(parser, PROTO_OP_MUL);
            break;
        case TOKEN_SLASH:
            emit_byte(parser, PROTO_OP_DIV);
            break;
        case TOKEN_EQUAL_EQUAL:
            emit_byte(parser, PROTO_OP_EQUAL);
            break;
        case TOKEN_BANG_EQUAL:
            emit_byte(parser, PROTO_OP_EQUAL);
            emit_byte(parser, PROTO_OP_NOT);
            break;
        case TOKEN_GREATER:
            emit_byte(parser, PROTO_OP_GREATER);
            break;
        case TOKEN_GREATER_EQUAL:
            emit_byte(parser, PROTO_OP_LESS);
            emit_byte(parser, PROTO_OP_NOT);
            break;
        case TOKEN_LESS:
            emit_byte(parser, PROTO_OP_LESS);
            break;
        case TOKEN_LESS_EQUAL:
            emit_byte(parser, PROTO_OP_GREATER);
            emit_byte(parser, PROTO_OP_NOT);
            break;
        default:
            break;
    }
}

static void parse_literal(Parser *parser, bool can_assign) {
    (void)can_assign;
    switch (parser->previous.type) {
        case TOKEN_TRUE:
            emit_byte(parser, PROTO_OP_TRUE);
            break;
        case TOKEN_FALSE:
            emit_byte(parser, PROTO_OP_FALSE);
            break;
        case TOKEN_NULL:
            emit_byte(parser, PROTO_OP_NULL);
            break;
        default:
            error(parser, "Unknown literal");
            break;
    }
}

static void parse_number(Parser *parser, bool can_assign) {
    (void)can_assign;
    char buffer[64];
    size_t length = parser->previous.length;
    if (length >= sizeof buffer) {
        error(parser, "Numeric literal too long");
        return;
    }
    memcpy(buffer, parser->previous.start, length);
    buffer[length] = '\0';
    double value = strtod(buffer, NULL);
    emit_number_literal(parser, value);
}

static void parse_string(Parser *parser, bool can_assign) {
    (void)can_assign;
    size_t length = parser->previous.length;
    if (length < 2) {
        error(parser, "Empty string literal");
        return;
    }
    const char *start = parser->previous.start + 1;
    size_t actual_length = length - 2;
    emit_constant(parser, proto_value_string(start, actual_length));
}

static void parse_and(Parser *parser, bool can_assign) {
    (void)can_assign;
    uint16_t end_jump = emit_jump(parser, PROTO_OP_JUMP_IF_FALSE);
    emit_byte(parser, PROTO_OP_POP);
    parse_precedence(parser, PREC_AND);
    patch_jump(parser, end_jump);
}

static void parse_or(Parser *parser, bool can_assign) {
    (void)can_assign;
    uint16_t else_jump = emit_jump(parser, PROTO_OP_JUMP_IF_FALSE);
    uint16_t end_jump = emit_jump(parser, PROTO_OP_JUMP);

    patch_jump(parser, else_jump);
    emit_byte(parser, PROTO_OP_POP);
    parse_precedence(parser, PREC_OR);
    patch_jump(parser, end_jump);
}

static void parse_variable(Parser *parser, bool can_assign) {
    Token name = parser->previous;
    CompilerContext *context = current_context(parser);
    int local_slot = resolve_local(parser, name);
    Local *local = (local_slot >= 0 && context) ? &context->locals[local_slot] : NULL;

    bool is_assignment = can_assign && match(parser, TOKEN_EQUAL);
    if (is_assignment) {
        if (local_slot >= 0) {
            if (local && local->is_const) {
                error(parser, "Cannot assign to const local");
                return;
            }
            parse_expression(parser);
            emit_set_local(parser, (uint8_t)local_slot, name.line);
            return;
        }
        int global_index = resolve_global(parser, name);
        if (global_index < 0) {
            return;
        }
        if (parser->globals.is_const[global_index] && parser->initializing_global != global_index) {
            error(parser, "Cannot assign to const global");
            return;
        }
        parse_expression(parser);
        emit_set_global(parser, &name, (uint16_t)global_index);
        return;
    }

    if (parser->current.type == TOKEN_LEFT_PAREN) {
        char identifier[PROTOHACK_MAX_IDENTIFIER + 1];
        bool is_native = false;
        if (token_to_identifier(&name, identifier, sizeof identifier)) {
            int native_index = protonative_index(identifier);
            if (native_index >= 0 && protonative_resolve(identifier)) {
                is_native = true;
            }
        }
        if (is_native) {
            parser_advance(parser);
            finish_native_call(parser, &name);
            return;
        }
        compile_named_call(parser, name, local_slot, false);
        return;
    }

    if (local_slot >= 0) {
        emit_get_local(parser, (uint8_t)local_slot, name.line);
        return;
    }

    int index = resolve_global(parser, name);
    if (index < 0) {
        return;
    }
    emit_get_global(parser, &name, (uint16_t)index);
}

static ParseRule rules[] = {
    [TOKEN_LEFT_PAREN] = {parse_grouping, NULL, PREC_NONE},
    [TOKEN_RIGHT_PAREN] = {NULL, NULL, PREC_NONE},
    [TOKEN_LEFT_BRACE] = {NULL, NULL, PREC_NONE},
    [TOKEN_RIGHT_BRACE] = {NULL, NULL, PREC_NONE},
    [TOKEN_COMMA] = {NULL, NULL, PREC_NONE},
    [TOKEN_DOT] = {NULL, NULL, PREC_NONE},
    [TOKEN_MINUS] = {parse_unary, parse_binary, PREC_TERM},
    [TOKEN_PLUS] = {NULL, parse_binary, PREC_TERM},
    [TOKEN_SEMICOLON] = {NULL, NULL, PREC_NONE},
    [TOKEN_SLASH] = {NULL, parse_binary, PREC_FACTOR},
    [TOKEN_STAR] = {NULL, parse_binary, PREC_FACTOR},
    [TOKEN_BANG] = {parse_unary, NULL, PREC_NONE},
    [TOKEN_BANG_EQUAL] = {NULL, parse_binary, PREC_EQUALITY},
    [TOKEN_EQUAL] = {NULL, NULL, PREC_NONE},
    [TOKEN_EQUAL_EQUAL] = {NULL, parse_binary, PREC_EQUALITY},
    [TOKEN_GREATER] = {NULL, parse_binary, PREC_COMPARISON},
    [TOKEN_GREATER_EQUAL] = {NULL, parse_binary, PREC_COMPARISON},
    [TOKEN_LESS] = {NULL, parse_binary, PREC_COMPARISON},
    [TOKEN_LESS_EQUAL] = {NULL, parse_binary, PREC_COMPARISON},
    [TOKEN_IDENTIFIER] = {parse_variable, NULL, PREC_NONE},
    [TOKEN_STRING] = {parse_string, NULL, PREC_NONE},
    [TOKEN_NUMBER] = {parse_number, NULL, PREC_NONE},
    [TOKEN_AND] = {NULL, parse_and, PREC_AND},
    [TOKEN_OR] = {NULL, parse_or, PREC_OR},
    [TOKEN_ELSE] = {NULL, NULL, PREC_NONE},
    [TOKEN_FALSE] = {parse_literal, NULL, PREC_NONE},
    [TOKEN_FOR] = {NULL, NULL, PREC_NONE},
    [TOKEN_IF] = {NULL, NULL, PREC_NONE},
    [TOKEN_LET] = {NULL, NULL, PREC_NONE},
    [TOKEN_NULL] = {parse_literal, NULL, PREC_NONE},
    [TOKEN_PRINT] = {NULL, NULL, PREC_NONE},
    [TOKEN_TRUE] = {parse_literal, NULL, PREC_NONE},
    [TOKEN_WHILE] = {NULL, NULL, PREC_NONE},
    [TOKEN_CONST] = {NULL, NULL, PREC_NONE},
    [TOKEN_CALL] = {parse_call_keyword, NULL, PREC_NONE},
    [TOKEN_CARVE] = {parse_carve, NULL, PREC_NONE},
    [TOKEN_PROBE] = {parse_probe, NULL, PREC_NONE},
    [TOKEN_EOF] = {NULL, NULL, PREC_NONE},
    [TOKEN_ERROR] = {NULL, NULL, PREC_NONE}
};

static ParseRule *get_rule(TokenType type) {
    return &rules[type];
}

static void parse_precedence(Parser *parser, Precedence precedence) {
    parser_advance(parser);
    ParseFn prefix_rule = get_rule(parser->previous.type)->prefix;
    if (!prefix_rule) {
        error(parser, "Expected expression");
        return;
    }

    bool can_assign = precedence <= PREC_ASSIGNMENT;
    prefix_rule(parser, can_assign);

    while (precedence <= get_rule(parser->current.type)->precedence) {
        parser_advance(parser);
        ParseFn infix = get_rule(parser->previous.type)->infix;
        if (infix) {
            infix(parser, can_assign);
        }
    }

    if (can_assign && match(parser, TOKEN_EQUAL)) {
        error(parser, "Invalid assignment target");
    }
}

static void parse_expression(Parser *parser) {
    parse_precedence(parser, PREC_ASSIGNMENT);
}

static void synchronize(Parser *parser) {
    parser->panic_mode = false;

    while (parser->current.type != TOKEN_EOF) {
        if (parser->previous.type == TOKEN_SEMICOLON) {
            return;
        }
        switch (parser->current.type) {
            case TOKEN_LET:
            case TOKEN_CONST:
            case TOKEN_PRINT:
            case TOKEN_IF:
            case TOKEN_WHILE:
            case TOKEN_FOR:
                return;
            default:
                break;
        }
        parser_advance(parser);
    }
}

static void block(Parser *parser) {
    begin_scope(parser);
    while (!check(parser, TOKEN_RIGHT_BRACE) && !check(parser, TOKEN_EOF)) {
        declaration(parser);
    }
    consume(parser, TOKEN_RIGHT_BRACE, "Expect '}' after block");
    end_scope(parser);
}

static void print_statement(Parser *parser) {
    parse_expression(parser);
    consume(parser, TOKEN_SEMICOLON, "Expect ';' after value");
    emit_byte(parser, PROTO_OP_PRINT);
}

static void expression_statement(Parser *parser) {
    parse_expression(parser);
    consume(parser, TOKEN_SEMICOLON, "Expect ';' after expression");
    emit_byte(parser, PROTO_OP_POP);
}

static void if_statement(Parser *parser) {
    consume(parser, TOKEN_LEFT_PAREN, "Expect '(' after 'if'");
    parse_expression(parser);
    consume(parser, TOKEN_RIGHT_PAREN, "Expect ')' after condition");

    uint16_t then_jump = emit_jump(parser, PROTO_OP_JUMP_IF_FALSE);
    emit_byte(parser, PROTO_OP_POP);
    statement(parser);

    uint16_t else_jump = emit_jump(parser, PROTO_OP_JUMP);
    patch_jump(parser, then_jump);
    emit_byte(parser, PROTO_OP_POP);

    if (match(parser, TOKEN_ELSE)) {
        statement(parser);
    }
    patch_jump(parser, else_jump);
}

static void while_statement(Parser *parser) {
    size_t loop_start = current_chunk(parser)->code_count;
    consume(parser, TOKEN_LEFT_PAREN, "Expect '(' after 'while'");
    parse_expression(parser);
    consume(parser, TOKEN_RIGHT_PAREN, "Expect ')' after condition");

    uint16_t exit_jump = emit_jump(parser, PROTO_OP_JUMP_IF_FALSE);
    emit_byte(parser, PROTO_OP_POP);
    statement(parser);
    emit_loop(parser, loop_start);

    patch_jump(parser, exit_jump);
    emit_byte(parser, PROTO_OP_POP);
}

static void for_statement(Parser *parser) {
    consume(parser, TOKEN_LEFT_PAREN, "Expect '(' after 'for'");

    if (match(parser, TOKEN_SEMICOLON)) {
    } else if (match(parser, TOKEN_LET)) {
        let_declaration(parser, false);
    } else if (match(parser, TOKEN_CONST)) {
        let_declaration(parser, true);
    } else {
        expression_statement(parser);
    }

    size_t loop_start = current_chunk(parser)->code_count;
    int exit_jump = -1;

    if (!match(parser, TOKEN_SEMICOLON)) {
        parse_expression(parser);
        consume(parser, TOKEN_SEMICOLON, "Expect ';' after loop condition");
        exit_jump = emit_jump(parser, PROTO_OP_JUMP_IF_FALSE);
        emit_byte(parser, PROTO_OP_POP);
    }

    if (!match(parser, TOKEN_RIGHT_PAREN)) {
        uint16_t body_jump = emit_jump(parser, PROTO_OP_JUMP);
        size_t increment_start = current_chunk(parser)->code_count;
        parse_expression(parser);
        emit_byte(parser, PROTO_OP_POP);
        consume(parser, TOKEN_RIGHT_PAREN, "Expect ')' after for clauses");
        emit_loop(parser, loop_start);
        loop_start = increment_start;
        patch_jump(parser, body_jump);
    }

    statement(parser);
    emit_loop(parser, loop_start);

    if (exit_jump != -1) {
        patch_jump(parser, (uint16_t)exit_jump);
        emit_byte(parser, PROTO_OP_POP);
    }
}

static void yield_statement(Parser *parser) {
    CompilerContext *context = current_context(parser);
    if (!context || context == &parser->root) {
        error(parser, "'yield' is only valid inside a function");
    }
    if (!check(parser, TOKEN_SEMICOLON)) {
        parse_expression(parser);
    } else {
        emit_byte(parser, PROTO_OP_NULL);
    }
    consume(parser, TOKEN_SEMICOLON, "Expect ';' after 'yield'");
    emit_byte(parser, PROTO_OP_RETURN);
}

static void etch_statement(Parser *parser) {
    ProtoTypeTag type_tag = require_callable_type(parser, "Expect type before '(' in etch");
    consume(parser, TOKEN_LEFT_PAREN, "Expect '(' after etch type");
    consume(parser, TOKEN_IDENTIFIER, "Expect memory identifier");
    Token memory_name = parser->previous;
    CompilerContext *context = current_context(parser);
    int local_slot = context ? resolve_local(parser, memory_name) : -1;
    int global_index = -1;
    if (local_slot >= 0) {
        emit_get_local(parser, (uint8_t)local_slot, memory_name.line);
    } else {
        global_index = resolve_global(parser, memory_name);
        if (global_index >= 0) {
            emit_get_global(parser, &memory_name, (uint16_t)global_index);
        }
    }
    consume(parser, TOKEN_COMMA, "Expect ',' after memory reference");
    parse_expression(parser);
    consume(parser, TOKEN_COMMA, "Expect ',' after index");
    parse_expression(parser);
    consume(parser, TOKEN_RIGHT_PAREN, "Expect ')' after etch arguments");
    consume(parser, TOKEN_SEMICOLON, "Expect ';' after etch statement");
    emit_byte(parser, PROTO_OP_STORE_TYPED);
    emit_byte(parser, (uint8_t)type_tag);
    if (local_slot >= 0) {
        emit_set_local(parser, (uint8_t)local_slot, memory_name.line);
    } else if (global_index >= 0) {
        emit_set_global(parser, &memory_name, (uint16_t)global_index);
    }
    emit_byte(parser, PROTO_OP_POP);
}

static void statement(Parser *parser) {
    if (match(parser, TOKEN_PRINT)) {
        print_statement(parser);
    } else if (match(parser, TOKEN_IF)) {
        if_statement(parser);
    } else if (match(parser, TOKEN_WHILE)) {
        while_statement(parser);
    } else if (match(parser, TOKEN_FOR)) {
        for_statement(parser);
    } else if (match(parser, TOKEN_YIELD)) {
        yield_statement(parser);
    } else if (match(parser, TOKEN_ETCH)) {
        etch_statement(parser);
    } else if (match(parser, TOKEN_LEFT_BRACE)) {
        block(parser);
    } else {
        expression_statement(parser);
    }
}

static void sync_function_globals(Parser *parser, ProtoChunk *chunk) {
    if (!parser || !chunk || chunk == parser->chunk) {
        return;
    }
    ProtoChunk *root = parser->chunk;
    if (chunk->globals) {
        for (size_t i = 0; i < chunk->globals_count; ++i) {
            free(chunk->globals[i]);
        }
        free(chunk->globals);
    }
    chunk->globals = NULL;
    chunk->globals_capacity = 0;
    chunk->globals_count = 0;

    if (!root->globals || root->globals_count == 0) {
        return;
    }

    chunk->globals = (char **)calloc(root->globals_count, sizeof(char *));
    if (!chunk->globals) {
        PROTOHACK_FATAL("Failed to copy globals for function");
    }
    chunk->globals_capacity = root->globals_count;
    chunk->globals_count = root->globals_count;
    for (size_t i = 0; i < root->globals_count; ++i) {
        const char *name = root->globals[i];
        chunk->globals[i] = protohack_copy_string(name, strlen(name));
    }
}

static void parse_function_body(Parser *parser, ProtoFunction *function) {
    (void)function;
    consume(parser, TOKEN_LEFT_BRACE, "Expect '{' before function body");
    begin_scope(parser);
    while (!check(parser, TOKEN_RIGHT_BRACE) && !check(parser, TOKEN_EOF)) {
        declaration(parser);
    }
    consume(parser, TOKEN_RIGHT_BRACE, "Expect '}' after function body");
    end_scope(parser);
}

static void craft_declaration(Parser *parser) {
    CompilerContext *enclosing = current_context(parser);
    if (enclosing && enclosing != &parser->root) {
        error(parser, "Nested 'craft' declarations are not supported yet");
        return;
    }

    consume(parser, TOKEN_IDENTIFIER, "Expect function name after 'craft'");
    Token name = parser->previous;

    char identifier[PROTOHACK_MAX_IDENTIFIER + 1];
    if (!token_to_identifier(&name, identifier, sizeof identifier)) {
        error(parser, "Identifier is too long");
        return;
    }

    int global_index = declare_global(parser, name, true);
    if (global_index < 0) {
        return;
    }

    parser->globals.defined[global_index] = true;

    ProtoFunction *function = proto_function_new(PROTO_FUNC_CRAFT, identifier);

    CompilerContext context = {0};
    context.function = function;
    context.chunk = &function->chunk;
    context.local_count = 0;
    context.scope_depth = 0;
    context.expected_return = PROTO_TYPE_NONE;
    context.enclosing = enclosing;

    Token synthetic = {.type = TOKEN_IDENTIFIER, .start = "", .length = 0, .line = name.line};
    context.locals[context.local_count++] = (Local){synthetic, 0, true, PROTO_TYPE_ANY};

    CompilerContext *previous = parser->compiler;
    parser->compiler = &context;

    consume(parser, TOKEN_LEFT_PAREN, "Expect '(' after function name");
    if (!check(parser, TOKEN_RIGHT_PAREN)) {
        do {
            if (function->arity >= PROTOHACK_MAX_PARAMS) {
                error(parser, "Too many parameters");
            }
            consume(parser, TOKEN_IDENTIFIER, "Expect parameter name");
            Token param_name = parser->previous;
            ProtoTypeTag param_type = PROTO_TYPE_ANY;
            if (match(parser, TOKEN_AS)) {
                param_type = parse_type_tag(parser);
            }
            if (function->arity < PROTOHACK_MAX_PARAMS) {
                function->param_types[function->arity] = param_type;
                function->arity++;
            }
            add_local(parser, param_name, false, param_type);
            CompilerContext *ctx = current_context(parser);
            if (ctx) {
                ctx->locals[ctx->local_count - 1].depth = 0;
            }
        } while (match(parser, TOKEN_COMMA));
    }
    consume(parser, TOKEN_RIGHT_PAREN, "Expect ')' after parameters");

    ProtoTypeTag return_type = PROTO_TYPE_NONE;
    if (match(parser, TOKEN_GIVES)) {
        return_type = parse_type_tag(parser);
    }
    function->return_type = return_type;
    context.expected_return = return_type;

    parse_function_body(parser, function);
    emit_return(parser);

    sync_function_globals(parser, &function->chunk);

    parser->compiler = previous;

    Token previous_token = parser->previous;
    parser->previous = name;
    emit_constant(parser, proto_value_function(function));
    parser->previous = previous_token;

    emit_set_global(parser, &name, (uint16_t)global_index);
    parser->globals.defined[global_index] = true;
    parser->globals.is_const[global_index] = true;

}

static void let_declaration(Parser *parser, bool is_const) {
    consume(parser, TOKEN_IDENTIFIER, "Expect identifier after declaration");
    Token name = parser->previous;

    ProtoTypeTag type_tag = PROTO_TYPE_ANY;
    if (match(parser, TOKEN_AS)) {
        type_tag = parse_type_tag(parser);
    }

    CompilerContext *context = current_context(parser);
    bool is_local = context && context != &parser->root;

    int index = -1;
    if (is_local) {
        add_local(parser, name, is_const, type_tag);
    } else {
        index = declare_global(parser, name, is_const);
        if (index < 0) {
            if (match(parser, TOKEN_EQUAL)) {
                parse_expression(parser);
            }
            consume(parser, TOKEN_SEMICOLON, "Expect ';' after declaration");
            return;
        }
    }

    bool has_initializer = match(parser, TOKEN_EQUAL);
    if (has_initializer) {
        if (!is_local) {
            parser->initializing_global = index;
        }
        parse_expression(parser);
        if (!is_local) {
            parser->initializing_global = -1;
        }
    } else {
        emit_byte(parser, PROTO_OP_NULL);
    }

    consume(parser, TOKEN_SEMICOLON, "Expect ';' after declaration");

    if (is_local) {
        mark_initialized(parser);
        if (is_const) {
            // const locals still reside on stack; no extra action needed
        }
    } else {
        emit_set_global(parser, &name, (uint16_t)index);
        parser->globals.defined[index] = true;
    }
}

static void declaration(Parser *parser) {
    if (match(parser, TOKEN_LET)) {
        let_declaration(parser, false);
    } else if (match(parser, TOKEN_CONST)) {
        let_declaration(parser, true);
    } else if (match(parser, TOKEN_CRAFT)) {
        craft_declaration(parser);
    } else {
        statement(parser);
    }

    if (parser->panic_mode) {
        synchronize(parser);
    }
}

bool protohack_compile_source(const char *source, ProtoChunk *chunk, ProtoError *error) {
    if (!source || !chunk || !error) {
        if (error) {
            protoerror_set(error, 0, "Invalid arguments to compiler");
        }
        return false;
    }

    protoerror_reset(error);

    Parser parser;
    parser_init(&parser, source, chunk, error);

    parser_advance(&parser);
    while (!check(&parser, TOKEN_EOF) && !parser.had_error) {
        declaration(&parser);
    }
    parser_advance(&parser);
    emit_return(&parser);

    return !parser.had_error;
}
