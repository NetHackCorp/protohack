#include "protohack/compiler.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>

#include "protohack/chunk.h"
#include "protohack/config.h"
#include "protohack/error.h"
#include "protohack/function.h"
#include "protohack/internal/common.h"
#include "protohack/native.h"
#include "protohack/opcode.h"
#include "protohack/serialize.h"
#include "protohack/types.h"
#include "protohack/value.h"

#define PROTOHACK_MAX_INCLUDE_DEPTH 32

typedef struct IncludeBuffer {
    char *data;
    size_t length;
    size_t capacity;
} IncludeBuffer;

static void includebuf_init(IncludeBuffer *buffer);
static void includebuf_free(IncludeBuffer *buffer);
static bool includebuf_append(IncludeBuffer *buffer, const char *data, size_t length);
static bool preprocess_includes_into(const char *source, const char *origin_path, ProtoError *error, int depth, IncludeBuffer *output);
static char *preprocess_includes(const char *source, const char *origin_path, ProtoError *error);

typedef enum {
    TOKEN_LEFT_PAREN,
    TOKEN_RIGHT_PAREN,
    TOKEN_LEFT_BRACE,
    TOKEN_RIGHT_BRACE,
    TOKEN_LEFT_BRACKET,
    TOKEN_RIGHT_BRACKET,
    TOKEN_COMMA,
    TOKEN_DOT,
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
    TOKEN_CLASS,
    TOKEN_CONST,
    TOKEN_ELSE,
    TOKEN_FALSE,
    TOKEN_FOR,
    TOKEN_FUN,
    TOKEN_IF,
    TOKEN_NULL,
    TOKEN_OR,
    TOKEN_PRINT,
    TOKEN_RETURN,
    TOKEN_SUPER,
    TOKEN_THIS,
    TOKEN_TRUE,
    TOKEN_VAR,
    TOKEN_WHILE,
    TOKEN_EOF,
    TOKEN_ERROR,
    TOKEN_LET,
    TOKEN_EXTEND,
    TOKEN_CALL,
    TOKEN_RAW,
    TOKEN_WITH,
    TOKEN_TRAIT,
    TOKEN_IMPLEMENT,
    TOKEN_ARROW,
    TOKEN_CRAFT,
    TOKEN_AMPERSAND,
    TOKEN_MATCH,
    TOKEN_CASE,
    TOKEN_DEFAULT,
    TOKEN_PIPE,
    TOKEN_TEXT,
    TOKEN_NUMERIC,
    TOKEN_AS,
    TOKEN_TYPE,
    TOKEN_YIELD,
    TOKEN_GIVES,
    TOKEN_POINTER,
    TOKEN_BREAK,
    TOKEN_CONTINUE,
    TOKEN_WHEN,
    TOKEN_CARVE,
    TOKEN_FLAG,
    TOKEN_ETCH,
    TOKEN_PROBE,
    TOKEN_NONE,
    TOKEN_LOOP,
    TOKEN_IMPORT,
    TOKEN_FROM,
    TOKEN_USING,
    TOKEN_LEFT_ANGLE,
    TOKEN_RIGHT_ANGLE,
    TOKEN_COLON,
    TOKEN_CLASSOF,
    TOKEN_CAST,
    TOKEN_NIL,
    TOKEN_WITHIN,
    TOKEN_MATCHES,
    TOKEN_SATISFIES,
    TOKEN_TEMPLATE,
    TOKEN_WHERE,
    TOKEN_INTERFACE,
    TOKEN_STRUCT,
    TOKEN_ENUM,
    TOKEN_IMPLEMENTS,
    TOKEN_MODULE,
    TOKEN_EXPORT,
    TOKEN_PRIVATE,
    TOKEN_PROTECTED,
    TOKEN_PUBLIC,
    TOKEN_STATIC,
    TOKEN_INLINE,
    TOKEN_OPERATOR,
    TOKEN_DEFER,
    TOKEN_USIZE,
    TOKEN_ISIZE,
    TOKEN_FLOAT,
    TOKEN_DOUBLE,
    TOKEN_I8,
    TOKEN_I16,
    TOKEN_I32,
    TOKEN_I64,
    TOKEN_U8,
    TOKEN_U16,
    TOKEN_U32,
    TOKEN_U64,
    TOKEN_BOOL,
    TOKEN_BYTE,
    TOKEN_SIZEOF,
    TOKEN_ALIGNOF,
    TOKEN_TRAITOF,
    TOKEN_OFFSETOF,
    TOKEN_DEDUCE,
    TOKEN_ASSIGN,
    TOKEN_LBRACE_EQUAL,
    TOKEN_RBRACE_EQUAL,
    TOKEN_WITHIN_MATCH,
    TOKEN_MATCH_WITHIN,
    TOKEN_FLOW,
    TOKEN_SOURCE,
    TOKEN_STAGE,
    TOKEN_SINK,
    TOKEN_EMIT,
    TOKEN_PULL,
    TOKEN_DRAIN,
    TOKEN_STOP,
    TOKEN_UNKNOWN
} TokenType;

typedef struct {
    TokenType type;
    const char *start;
    size_t length;
    size_t line;
} Token;

typedef struct {
    const char *source;
    const char *start;
    const char *current;
    size_t line;
} Scanner;

static void scanner_init(Scanner *scanner, const char *source) {
    scanner->source = source;
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

static bool scanner_is_identifier_start(char c) {
    unsigned char uc = (unsigned char)c;
    return (uc >= 'a' && uc <= 'z') || (uc >= 'A' && uc <= 'Z') || uc == '_' || uc >= 0x80;
}

static bool scanner_is_identifier_part(char c) {
    unsigned char uc = (unsigned char)c;
    if (uc >= '0' && uc <= '9') {
        return true;
    }
    return scanner_is_identifier_start(c);
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
            if (token->length == 5 && memcmp(token->start, "class", 5) == 0) {
                return TOKEN_CLASS;
            }
            if (token->length == 4 && memcmp(token->start, "call", 4) == 0) {
                return TOKEN_CALL;
            }
            if (token->length == 5 && memcmp(token->start, "carve", 5) == 0) {
                return TOKEN_CARVE;
            }
            break;
        case 'd':
            if (token->length == 5 && memcmp(token->start, "drain", 5) == 0) {
                return TOKEN_DRAIN;
            }
            break;
        case 'e':
            if (token->length == 4 && memcmp(token->start, "else", 4) == 0) {
                return TOKEN_ELSE;
            }
            if (token->length == 4 && memcmp(token->start, "etch", 4) == 0) {
                return TOKEN_ETCH;
            }
            if (token->length == 6 && memcmp(token->start, "extend", 6) == 0) {
                return TOKEN_EXTEND;
            }
            if (token->length == 4 && memcmp(token->start, "emit", 4) == 0) {
                return TOKEN_EMIT;
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
            if (token->length == 4 && memcmp(token->start, "flow", 4) == 0) {
                return TOKEN_FLOW;
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
            if (token->length == 7 && memcmp(token->start, "pointer", 7) == 0) {
                return TOKEN_POINTER;
            }
            if (token->length == 4 && memcmp(token->start, "pull", 4) == 0) {
                return TOKEN_PULL;
            }
            break;
        case 's':
            if (token->length == 5 && memcmp(token->start, "stage", 5) == 0) {
                return TOKEN_STAGE;
            }
            if (token->length == 4 && memcmp(token->start, "sink", 4) == 0) {
                return TOKEN_SINK;
            }
            if (token->length == 6 && memcmp(token->start, "source", 6) == 0) {
                return TOKEN_SOURCE;
            }
            if (token->length == 4 && memcmp(token->start, "stop", 4) == 0) {
                return TOKEN_STOP;
            }
            break;
        case 't':
            if (token->length == 4 && memcmp(token->start, "true", 4) == 0) {
                return TOKEN_TRUE;
            }
            if (token->length == 4 && memcmp(token->start, "text", 4) == 0) {
                return TOKEN_TEXT;
            }
            if (token->length == 4 && memcmp(token->start, "this", 4) == 0) {
                return TOKEN_THIS;
            }
            break;
        case 'w':
            if (token->length == 5 && memcmp(token->start, "while", 5) == 0) {
                return TOKEN_WHILE;
            }
            if (token->length == 4 && memcmp(token->start, "with", 4) == 0) {
                return TOKEN_WITH;
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
    while (scanner_is_identifier_part(scanner_peek(scanner))) {
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

    if (scanner_is_identifier_start(c)) {
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
    case '&': return scanner_make_token(scanner, TOKEN_AMPERSAND);
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
    ProtoFunction *function_value;
} Local;

typedef struct CompilerContext {
    ProtoFunction *function;
    ProtoChunk *chunk;
    Local locals[PROTOHACK_MAX_LOCALS];
    int local_count;
    int scope_depth;
    ProtoTypeTag expected_return;
    Token type_params[PROTOHACK_MAX_TYPE_PARAMS];
    uint8_t type_param_count;
    ProtoTypeBindingSet bindings;
    struct CompilerContext *enclosing;
} CompilerContext;

typedef struct ClassCompiler {
    Token name;
    Token type_params[PROTOHACK_MAX_TYPE_PARAMS];
    char type_param_names[PROTOHACK_MAX_TYPE_PARAMS][PROTOHACK_MAX_IDENTIFIER + 1];
    uint8_t type_param_count;
    ProtoTypeBindingSet bindings;
    struct ClassCompiler *enclosing;
} ClassCompiler;

typedef struct TypeParameterList {
    Token tokens[PROTOHACK_MAX_TYPE_PARAMS];
    char names[PROTOHACK_MAX_TYPE_PARAMS][PROTOHACK_MAX_IDENTIFIER + 1];
    uint8_t count;
} TypeParameterList;

#define PROTOHACK_MAX_TEMPLATE_NAME 192
#define PROTOHACK_MAX_FUNCTION_TEMPLATES 128
#define PROTOHACK_MAX_FUNCTION_SPECIALIZATIONS 256

typedef struct TemplateArg {
    ProtoTypeTag tag;
    int8_t param_index;
    const CompilerContext *context;
    const ClassCompiler *klass;
    bool unresolved;
    char label[PROTOHACK_MAX_IDENTIFIER + 1];
} TemplateArg;

typedef struct TemplateArgList {
    TemplateArg args[PROTOHACK_MAX_TYPE_PARAMS];
    uint8_t count;
} TemplateArgList;

typedef struct FunctionTemplateEntry {
    char name[PROTOHACK_MAX_IDENTIFIER + 1];
    ProtoFunction *function;
    uint8_t type_param_count;
} FunctionTemplateEntry;

typedef struct FunctionSpecializationEntry {
    char name[PROTOHACK_MAX_TEMPLATE_NAME];
    uint16_t constant_index;
    ProtoFunction *function;
} FunctionSpecializationEntry;

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
        ProtoTypeTag type_tags[PROTOHACK_MAX_GLOBALS];
        ProtoFunction *functions[PROTOHACK_MAX_GLOBALS];
    } globals;
    int initializing_global;
    CompilerContext *compiler;
    CompilerContext root;
    ClassCompiler *current_class;
    struct {
        FunctionTemplateEntry function_templates[PROTOHACK_MAX_FUNCTION_TEMPLATES];
        size_t function_template_count;
        FunctionSpecializationEntry function_specializations[PROTOHACK_MAX_FUNCTION_SPECIALIZATIONS];
        size_t function_specialization_count;
    } generics;
    ProtoTypeTag expression_type;
    ProtoFunction *recent_function_value;
    ProtoTypeTag argument_types[PROTOHACK_MAX_PARAMS];
    uint8_t argument_count;
} Parser;

static void parser_advance(Parser *parser);
static void parse_expression(Parser *parser);
static void declaration(Parser *parser);
static ParseRule *get_rule(TokenType type);
static void parse_precedence(Parser *parser, Precedence precedence);
static void statement(Parser *parser);
static void error(Parser *parser, const char *message);
static void let_declaration(Parser *parser, bool is_const);
static CompilerContext *current_context(Parser *parser);
static void begin_scope(Parser *parser);
static void end_scope(Parser *parser);
static void add_local(Parser *parser, Token name, bool is_const, ProtoTypeTag type_tag);
static int resolve_local(Parser *parser, Token name);
static void mark_initialized(Parser *parser);
static bool resolve_type_parameter_source(Parser *parser, const Token *identifier, int8_t *out_index, const CompilerContext **out_context, const ClassCompiler **out_class);
static int8_t resolve_type_parameter_index(Parser *parser, const Token *identifier);
static ProtoTypeTag parse_type_annotation(Parser *parser, int8_t *out_type_param_index);
static ProtoTypeTag parse_type_tag(Parser *parser);
static ProtoTypeTag require_callable_type(Parser *parser, const char *message);
static void emit_byte(Parser *parser, uint8_t byte);
static uint8_t parse_call_arguments(Parser *parser);
static void compile_named_call(Parser *parser, Token name, int local_slot, bool paren_consumed);
static void parse_call_keyword(Parser *parser, bool can_assign);
static void parse_carve(Parser *parser, bool can_assign);
static void parse_probe(Parser *parser, bool can_assign);
static void craft_declaration(Parser *parser);
static void class_declaration(Parser *parser);
static void extend_declaration(Parser *parser);
static void extension_spec_reset(ProtoExtensionTypeSpec *spec);
static bool populate_extension_spec(Parser *parser, const Token *token, const char *name, const TemplateArgList *args, ProtoExtensionTypeSpec *out_spec);
static void method_declaration(Parser *parser, Token class_name);
static void parse_function_body(Parser *parser, ProtoFunction *function);
static void yield_statement(Parser *parser);
static void etch_statement(Parser *parser);
static void sync_function_globals(Parser *parser, ProtoChunk *chunk);
static void finalize_module_metadata(Parser *parser);
static bool token_to_identifier(const Token *token, char *buffer, size_t buffer_size);
static void parse_this(Parser *parser, bool can_assign);
static void parse_dot(Parser *parser, bool can_assign);
static void parse_address(Parser *parser, bool can_assign);
static void parse_pointer_deref(Parser *parser, bool can_assign);
static void emit_address_of_local(Parser *parser, uint8_t slot, bool is_const, size_t line);
static void emit_address_of_global(Parser *parser, uint16_t index, bool is_const, size_t line);
static bool tokens_equal(const Token *a, const Token *b);
static bool identifier_matches_type_param(const Token *identifier, const Token *param);
static bool is_type_parameter(Parser *parser, const Token *identifier);
static void parse_type_parameter_list(Parser *parser, const char *context_label, TypeParameterList *list);
static bool parse_template_type_atom(Parser *parser, TemplateArg *out_arg);
static bool try_parse_template_arguments(Parser *parser, TemplateArgList *out_args);
static FunctionTemplateEntry *find_function_template(Parser *parser, const char *name);
static bool register_function_template(Parser *parser, const char *name, ProtoFunction *function, uint8_t type_param_count);
static FunctionSpecializationEntry *find_function_specialization(Parser *parser, const char *name);
static bool add_function_specialization(Parser *parser, const char *name, uint16_t constant_index, ProtoFunction *function);
static bool ensure_function_specialization(Parser *parser, const Token *name_token, const char *base_name, const TemplateArgList *args, uint16_t *out_constant_index, ProtoFunction **out_function);
static void emit_constant_index(Parser *parser, uint16_t index, size_t line);
static void compiler_context_reset_bindings(CompilerContext *context);
static void class_compiler_reset_bindings(ClassCompiler *klass);
static ProtoTypeBinding resolve_template_argument_binding(const TemplateArg *arg);
static void parser_reset_expression(Parser *parser);
static void parser_set_expression(Parser *parser, ProtoTypeTag type, ProtoFunction *function);
static void validate_call_arguments(Parser *parser, const Token *name_token, const ProtoFunction *function, uint8_t provided_count);
static bool extension_binding_is_concrete(const ProtoTypeBinding *binding);
static bool validate_extension_contract(Parser *parser, const Token *target_token, ProtoExtensionDecl *decl);
static const ProtoFunction *resolve_extension_craft_template(Parser *parser, const ProtoExtensionDecl *decl);
static ProtoTypeTag resolve_extension_specialized_type(const ProtoFunction *template_function,
                                                       const ProtoTypeBindingSet *bindings,
                                                       ProtoTypeTag default_tag,
                                                       int8_t binding_index);
static void extend_craft(Parser *parser, Token keyword);

static void compiler_context_reset_bindings(CompilerContext *context) {
    if (!context) {
        return;
    }
    context->bindings.count = 0;
    for (uint8_t i = 0; i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
        context->bindings.entries[i].tag = PROTO_TYPE_ANY;
        context->bindings.entries[i].param = -1;
    }
    uint8_t param_count = context->type_param_count;
    if (param_count > PROTOHACK_MAX_TYPE_PARAMS) {
        param_count = PROTOHACK_MAX_TYPE_PARAMS;
    }
    context->bindings.count = param_count;
    for (uint8_t i = 0; i < param_count; ++i) {
        context->bindings.entries[i].param = (int8_t)i;
    }
    if (!context->function) {
        return;
    }
    const ProtoFunction *function = context->function;
    uint8_t binding_count = function->bindings.count;
    if (binding_count > PROTOHACK_MAX_TYPE_PARAMS) {
        binding_count = PROTOHACK_MAX_TYPE_PARAMS;
    }
    if (binding_count > context->bindings.count) {
        context->bindings.count = binding_count;
    }
    for (uint8_t i = 0; i < binding_count; ++i) {
        context->bindings.entries[i] = function->bindings.entries[i];
    }
    uint8_t arg_count = function->type_argument_count;
    if (arg_count > PROTOHACK_MAX_TYPE_PARAMS) {
        arg_count = PROTOHACK_MAX_TYPE_PARAMS;
    }
    if (arg_count > context->bindings.count) {
        context->bindings.count = arg_count;
    }
    for (uint8_t i = 0; i < arg_count; ++i) {
        ProtoTypeTag argument = function->type_arguments[i];
        if (argument != PROTO_TYPE_ANY) {
            context->bindings.entries[i].tag = argument;
            context->bindings.entries[i].param = -1;
        }
    }
}

static void class_compiler_reset_bindings(ClassCompiler *klass) {
    if (!klass) {
        return;
    }
    klass->bindings.count = 0;
    for (uint8_t i = 0; i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
        klass->bindings.entries[i].tag = PROTO_TYPE_ANY;
        klass->bindings.entries[i].param = -1;
    }
    uint8_t param_count = klass->type_param_count;
    if (param_count > PROTOHACK_MAX_TYPE_PARAMS) {
        param_count = PROTOHACK_MAX_TYPE_PARAMS;
    }
    klass->bindings.count = param_count;
    for (uint8_t i = 0; i < param_count; ++i) {
        klass->bindings.entries[i].param = (int8_t)i;
    }
}

static ProtoTypeBinding resolve_template_argument_binding(const TemplateArg *arg) {
    ProtoTypeBinding binding;
    binding.tag = PROTO_TYPE_ANY;
    binding.param = -1;

    if (!arg) {
        return binding;
    }

    if (arg->param_index >= 0) {
        binding.param = arg->param_index;
    }

    const ProtoTypeBinding *source = NULL;
    if (arg->context && arg->param_index >= 0 && (uint8_t)arg->param_index < arg->context->bindings.count) {
        source = &arg->context->bindings.entries[arg->param_index];
    } else if (arg->klass && arg->param_index >= 0 && (uint8_t)arg->param_index < arg->klass->bindings.count) {
        source = &arg->klass->bindings.entries[arg->param_index];
    }

    if (source) {
        binding = *source;
        if (binding.tag == PROTO_TYPE_ANY && binding.param < 0 && arg->param_index >= 0) {
            binding.param = arg->param_index;
        }
    }

    if (binding.tag == PROTO_TYPE_ANY && arg->tag != PROTO_TYPE_ANY) {
        binding.tag = arg->tag;
        binding.param = -1;
    }

    if (binding.tag != PROTO_TYPE_ANY) {
        binding.param = -1;
    }

    return binding;
}

static void extension_spec_reset(ProtoExtensionTypeSpec *spec) {
    if (!spec) {
        return;
    }
    memset(spec->name, 0, sizeof spec->name);
    spec->label_count = 0;
    spec->bindings.count = 0;
    for (uint8_t i = 0; i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
        spec->bindings.entries[i].tag = PROTO_TYPE_ANY;
        spec->bindings.entries[i].param = -1;
        memset(spec->labels[i], 0, sizeof spec->labels[i]);
    }
}

static bool populate_extension_spec(Parser *parser, const Token *token, const char *name, const TemplateArgList *args, ProtoExtensionTypeSpec *out_spec) {
    if (!parser || !name || !out_spec) {
        return false;
    }

    TemplateArgList empty_args = {0};
    const TemplateArgList *list = args ? args : &empty_args;

    extension_spec_reset(out_spec);
    strncpy(out_spec->name, name, sizeof out_spec->name - 1);
    out_spec->name[sizeof out_spec->name - 1] = '\0';

    if (list->count > PROTOHACK_MAX_TYPE_PARAMS) {
        char message[128];
        snprintf(message, sizeof message, "Too many type arguments supplied to '%s'", name);
        Token saved = parser->previous;
        if (token) {
            parser->previous = *token;
        }
        error(parser, message);
        if (token) {
            parser->previous = saved;
        }
        return false;
    }

    uint8_t arg_count = list->count;
    out_spec->bindings.count = arg_count;

    for (uint8_t i = 0; i < arg_count; ++i) {
        const TemplateArg *arg = &list->args[i];
        ProtoTypeBinding binding = resolve_template_argument_binding(arg);
        out_spec->bindings.entries[i] = binding;

        const char *label = arg->label;
        if (!label || label[0] == '\0') {
            if (arg->tag != PROTO_TYPE_ANY) {
                label = proto_type_tag_name(arg->tag);
            }
        }
        if (!label) {
            label = "";
        }
        strncpy(out_spec->labels[i], label, sizeof out_spec->labels[i] - 1);
        out_spec->labels[i][sizeof out_spec->labels[i] - 1] = '\0';

        bool unresolved = arg->unresolved;
        bool missing_binding = (!unresolved && binding.tag == PROTO_TYPE_ANY && binding.param < 0);
        if (unresolved || missing_binding) {
            char message[256];
            const char *display = out_spec->labels[i];
            if (!display || display[0] == '\0') {
                display = "unknown";
            }
            if (unresolved) {
                snprintf(message, sizeof message, "Unknown type argument '%s' supplied to '%s'", display, name);
            } else {
                snprintf(message, sizeof message, "Unable to resolve type argument %u for '%s'", (unsigned)(i + 1), name);
            }
            Token saved = parser->previous;
            if (token) {
                parser->previous = *token;
            }
            error(parser, message);
            if (token) {
                parser->previous = saved;
            }
            return false;
        }
    }

    out_spec->label_count = arg_count;
    return true;
}

static void parser_reset_expression(Parser *parser) {
    if (!parser) {
        return;
    }
    parser->expression_type = PROTO_TYPE_ANY;
    parser->recent_function_value = NULL;
}

static void parser_set_expression(Parser *parser, ProtoTypeTag type, ProtoFunction *function) {
    if (!parser) {
        return;
    }
    parser->expression_type = type;
    parser->recent_function_value = function;
}

static void parser_init(Parser *parser, const char *source, ProtoChunk *chunk, ProtoError *error) {
    scanner_init(&parser->scanner, source);
    parser->had_error = false;
    parser->panic_mode = false;
    parser->chunk = chunk;
    parser->error = error;
    memset(parser->globals.defined, 0, sizeof parser->globals.defined);
    memset(parser->globals.is_const, 0, sizeof parser->globals.is_const);
    memset(parser->globals.type_tags, 0, sizeof parser->globals.type_tags);
    memset(parser->globals.functions, 0, sizeof parser->globals.functions);
    parser->initializing_global = -1;
    parser->root.function = NULL;
    parser->root.chunk = chunk;
    parser->root.local_count = 0;
    parser->root.scope_depth = 0;
    parser->root.expected_return = PROTO_TYPE_NONE;
    parser->root.type_param_count = 0;
    memset(parser->root.type_params, 0, sizeof parser->root.type_params);
    compiler_context_reset_bindings(&parser->root);
    parser->root.enclosing = NULL;
    parser->compiler = &parser->root;
    parser->current_class = NULL;
    memset(parser->generics.function_templates, 0, sizeof parser->generics.function_templates);
    parser->generics.function_template_count = 0;
    memset(parser->generics.function_specializations, 0, sizeof parser->generics.function_specializations);
    parser->generics.function_specialization_count = 0;
    parser->expression_type = PROTO_TYPE_ANY;
    parser->recent_function_value = NULL;
    memset(parser->argument_types, 0, sizeof parser->argument_types);
    parser->argument_count = 0;
}

static void includebuf_init(IncludeBuffer *buffer) {
    if (!buffer) {
        return;
    }
    buffer->data = NULL;
    buffer->length = 0;
    buffer->capacity = 0;
}

static bool includebuf_reserve(IncludeBuffer *buffer, size_t additional) {
    if (!buffer) {
        return false;
    }
    size_t required = buffer->length + additional + 1;
    if (required <= buffer->capacity) {
        return true;
    }
    size_t new_capacity = buffer->capacity == 0 ? 256 : buffer->capacity;
    while (new_capacity < required) {
        new_capacity *= 2;
    }
    char *new_data = (char *)realloc(buffer->data, new_capacity);
    if (!new_data) {
        return false;
    }
    buffer->data = new_data;
    buffer->capacity = new_capacity;
    return true;
}

static bool includebuf_append(IncludeBuffer *buffer, const char *data, size_t length) {
    if (!buffer || !data || length == 0) {
        if (buffer && buffer->data) {
            buffer->data[buffer->length] = '\0';
        }
        return true;
    }
    if (!includebuf_reserve(buffer, length)) {
        return false;
    }
    memcpy(buffer->data + buffer->length, data, length);
    buffer->length += length;
    buffer->data[buffer->length] = '\0';
    return true;
}

static void includebuf_free(IncludeBuffer *buffer) {
    if (!buffer) {
        return;
    }
    free(buffer->data);
    buffer->data = NULL;
    buffer->length = 0;
    buffer->capacity = 0;
}

static bool is_path_separator(char c) {
    return c == '/' || c == '\\';
}

static bool path_is_absolute(const char *path) {
    if (!path || path[0] == '\0') {
        return false;
    }
#if defined(_WIN32)
    if (isalpha((unsigned char)path[0]) && path[1] == ':' && is_path_separator(path[2])) {
        return true;
    }
    if (is_path_separator(path[0]) && is_path_separator(path[1])) {
        return true;
    }
    return false;
#else
    return path[0] == '/';
#endif
}

static char *extract_directory(const char *path) {
    if (!path || path[0] == '\0') {
        return NULL;
    }
    const char *last_slash = strrchr(path, '/');
#if defined(_WIN32)
    const char *last_backslash = strrchr(path, '\\');
    if (!last_slash || (last_backslash && last_backslash > last_slash)) {
        last_slash = last_backslash;
    }
#endif
    if (!last_slash) {
        return NULL;
    }
    size_t length = (size_t)(last_slash - path + 1);
    return protohack_copy_string(path, length);
}

static char *join_path(const char *directory, const char *relative) {
    if (!relative) {
        return NULL;
    }
    if (!directory || directory[0] == '\0' || path_is_absolute(relative)) {
        return protohack_copy_string(relative, strlen(relative));
    }
    size_t dir_length = strlen(directory);
    bool has_sep = dir_length > 0 && is_path_separator(directory[dir_length - 1]);
    size_t relative_length = strlen(relative);
    size_t total = dir_length + (has_sep ? 0 : 1) + relative_length;
    char *combined = (char *)malloc(total + 1);
    if (!combined) {
        return NULL;
    }
    memcpy(combined, directory, dir_length);
    size_t index = dir_length;
    if (!has_sep) {
#if defined(_WIN32)
        combined[index++] = '\\';
#else
        combined[index++] = '/';
#endif
    }
    memcpy(combined + index, relative, relative_length);
    combined[index + relative_length] = '\0';
    return combined;
}

static size_t compute_column(const char *source, const char *position) {
    if (!source || !position) {
        return 0;
    }
    const char *cursor = position;
    while (cursor > source && cursor[-1] != '\n') {
        cursor--;
    }
    return (size_t)(position - cursor) + 1u;
}

static char *read_file_contents(const char *path, ProtoError *error, size_t line, size_t column) {
    if (!path) {
        if (error && error->ok) {
            protoerror_set_with_column(error, line, column, "Include path is empty");
        }
        return NULL;
    }
    FILE *file = fopen(path, "rb");
    if (!file) {
        if (error && error->ok) {
            protoerror_set_with_column(error, line, column, "Unable to open include file '%s'", path);
        }
        return NULL;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        if (error && error->ok) {
            protoerror_set_with_column(error, line, column, "Failed to read include file '%s'", path);
        }
        return NULL;
    }
    long size = ftell(file);
    if (size < 0) {
        fclose(file);
        if (error && error->ok) {
            protoerror_set_with_column(error, line, column, "Failed to determine size of include file '%s'", path);
        }
        return NULL;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        if (error && error->ok) {
            protoerror_set_with_column(error, line, column, "Failed to rewind include file '%s'", path);
        }
        return NULL;
    }
    char *buffer = (char *)malloc((size_t)size + 1);
    if (!buffer) {
        fclose(file);
        if (error && error->ok) {
            protoerror_set_with_column(error, line, column, "Out of memory while reading include '%s'", path);
        }
        return NULL;
    }
    size_t read = fread(buffer, 1, (size_t)size, file);
    fclose(file);
    if (read != (size_t)size) {
        free(buffer);
        if (error && error->ok) {
            protoerror_set_with_column(error, line, column, "Failed to read include file '%s'", path);
        }
        return NULL;
    }
    buffer[size] = '\0';
    return buffer;
}

static bool preprocess_includes_into(const char *source, const char *origin_path, ProtoError *error, int depth, IncludeBuffer *output) {
    if (!source) {
        return includebuf_append(output, "", 0);
    }
    if (depth > PROTOHACK_MAX_INCLUDE_DEPTH) {
        if (error && error->ok) {
            protoerror_set(error, 0, "Maximum include depth exceeded");
        }
        return false;
    }

    char *origin_dir = extract_directory(origin_path);
    Scanner scanner;
    scanner_init(&scanner, source);
    const char *emit_start = source;

    for (;;) {
        Token token = scanner_scan_token(&scanner);
        if (token.type == TOKEN_EOF) {
            if (!includebuf_append(output, emit_start, (size_t)(token.start - emit_start))) {
                if (error && error->ok) {
                    protoerror_set(error, 0, "Out of memory while processing includes");
                }
                free(origin_dir);
                return false;
            }
            break;
        }

        if (token.type == TOKEN_IDENTIFIER && token.length == 3 && memcmp(token.start, "inc", 3) == 0) {
            Scanner lookahead = scanner;
            Token left_paren = scanner_scan_token(&lookahead);
            if (left_paren.type != TOKEN_LEFT_PAREN) {
                continue;
            }
            Token path_token = scanner_scan_token(&lookahead);
            if (path_token.type != TOKEN_STRING) {
                continue;
            }
            Token right_paren = scanner_scan_token(&lookahead);
            if (right_paren.type != TOKEN_RIGHT_PAREN) {
                continue;
            }
            Token semicolon = scanner_scan_token(&lookahead);
            if (semicolon.type != TOKEN_SEMICOLON) {
                size_t column = compute_column(source, token.start);
                if (error && error->ok) {
                    protoerror_set_with_column(error, token.line, column, "Include directive must end with ';'");
                }
                free(origin_dir);
                return false;
            }

            if (!includebuf_append(output, emit_start, (size_t)(token.start - emit_start))) {
                if (error && error->ok) {
                    protoerror_set(error, token.line, "Out of memory while processing includes");
                }
                free(origin_dir);
                return false;
            }

            size_t literal_length = path_token.length >= 2 ? path_token.length - 2 : 0;
            char *literal = protohack_copy_string(path_token.start + 1, literal_length);
            char *resolved = join_path(origin_dir, literal);
            if (!resolved) {
                if (error && error->ok) {
                    size_t column = compute_column(source, token.start);
                    protoerror_set_with_column(error, token.line, column, "Unable to resolve include path '%s'", literal);
                }
                free(literal);
                free(origin_dir);
                return false;
            }

            size_t column = compute_column(source, token.start);
            char *file_contents = read_file_contents(resolved, error, token.line, column);
            if (!file_contents) {
                free(literal);
                free(resolved);
                free(origin_dir);
                return false;
            }

            IncludeBuffer nested;
            includebuf_init(&nested);
            bool ok = preprocess_includes_into(file_contents, resolved, error, depth + 1, &nested);
            free(file_contents);
            if (!ok) {
                includebuf_free(&nested);
                free(literal);
                free(resolved);
                free(origin_dir);
                return false;
            }

            if (!includebuf_append(output, nested.data, nested.length)) {
                includebuf_free(&nested);
                free(literal);
                free(resolved);
                free(origin_dir);
                if (error && error->ok) {
                    protoerror_set(error, token.line, "Out of memory while expanding includes");
                }
                return false;
            }

            includebuf_free(&nested);
            free(literal);
            free(resolved);
            emit_start = lookahead.current;
            scanner = lookahead;
        }
    }

    free(origin_dir);
    return true;
}

static char *preprocess_includes(const char *source, const char *origin_path, ProtoError *error) {
    IncludeBuffer buffer;
    includebuf_init(&buffer);
    if (!preprocess_includes_into(source, origin_path, error, 0, &buffer)) {
        includebuf_free(&buffer);
        return NULL;
    }
    if (!buffer.data) {
        buffer.data = protohack_copy_string("", 0);
    }
    return buffer.data;
}

#define SUGGESTION_NO_MATCH ((size_t)-1)

static size_t min_size_t(size_t a, size_t b, size_t c) {
    size_t m = a < b ? a : b;
    return m < c ? m : c;
}

static bool strings_equal_ci(const char *a, const char *b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return false;
        }
        ++a;
        ++b;
    }
    return *a == *b;
}

static size_t levenshtein_distance_ci(const char *a, const char *b) {
    if (!a || !b) {
        return SUGGESTION_NO_MATCH;
    }
    size_t len_a = strlen(a);
    size_t len_b = strlen(b);
    if (len_b > PROTOHACK_MAX_IDENTIFIER) {
        len_b = PROTOHACK_MAX_IDENTIFIER;
    }
    if (len_a > PROTOHACK_MAX_IDENTIFIER) {
        len_a = PROTOHACK_MAX_IDENTIFIER;
    }
    size_t prev[PROTOHACK_MAX_IDENTIFIER + 1];
    size_t curr[PROTOHACK_MAX_IDENTIFIER + 1];

    for (size_t j = 0; j <= len_b; ++j) {
        prev[j] = j;
    }

    for (size_t i = 1; i <= len_a; ++i) {
        curr[0] = i;
        for (size_t j = 1; j <= len_b; ++j) {
            size_t cost = tolower((unsigned char)a[i - 1]) == tolower((unsigned char)b[j - 1]) ? 0u : 1u;
            curr[j] = min_size_t(prev[j] + 1u, curr[j - 1] + 1u, prev[j - 1] + cost);
        }
        for (size_t j = 0; j <= len_b; ++j) {
            prev[j] = curr[j];
        }
    }

    return prev[len_b];
}

static size_t suggestion_threshold(size_t length) {
    if (length <= 4u) {
        return 1u;
    }
    if (length <= 6u) {
        return 2u;
    }
    return 3u;
}

static void update_best_suggestion(const char *input, const char *candidate, size_t *best_distance, char *best_name, size_t best_name_size) {
    if (!candidate || candidate[0] == '\0' || strings_equal_ci(input, candidate)) {
        return;
    }
    size_t distance = levenshtein_distance_ci(input, candidate);
    if (distance < *best_distance) {
        *best_distance = distance;
        strncpy(best_name, candidate, best_name_size - 1);
        best_name[best_name_size - 1] = '\0';
    }
}

static bool suggest_identifier(Parser *parser, const char *identifier, char *out_name, size_t out_size, size_t *out_distance) {
    if (!identifier || !out_name || out_size == 0) {
        return false;
    }

    size_t best_distance = SUGGESTION_NO_MATCH;
    out_name[0] = '\0';

    CompilerContext *context = current_context(parser);
    while (context) {
        for (int i = 0; i < context->local_count; ++i) {
            char candidate[PROTOHACK_MAX_IDENTIFIER + 1];
            if (!token_to_identifier(&context->locals[i].name, candidate, sizeof candidate)) {
                continue;
            }
            update_best_suggestion(identifier, candidate, &best_distance, out_name, out_size);
        }
        context = context->enclosing;
    }

    if (parser && parser->chunk && parser->chunk->globals) {
        for (size_t i = 0; i < parser->chunk->globals_count; ++i) {
            const char *candidate = parser->chunk->globals[i];
            update_best_suggestion(identifier, candidate, &best_distance, out_name, out_size);
        }
    }

    const ProtoNativeEntry *native_table = protonative_table();
    size_t native_count = protonative_count();
    for (size_t i = 0; i < native_count; ++i) {
        update_best_suggestion(identifier, native_table[i].name, &best_distance, out_name, out_size);
    }

    if (out_distance) {
        *out_distance = best_distance;
    }
    return out_name[0] != '\0';
}

static bool suggest_native_identifier(const char *identifier, char *out_name, size_t out_size, size_t *out_distance) {
    if (!identifier || !out_name || out_size == 0) {
        return false;
    }

    size_t best_distance = SUGGESTION_NO_MATCH;
    out_name[0] = '\0';

    const ProtoNativeEntry *native_table = protonative_table();
    size_t native_count = protonative_count();
    for (size_t i = 0; i < native_count; ++i) {
        update_best_suggestion(identifier, native_table[i].name, &best_distance, out_name, out_size);
    }

    if (out_distance) {
        *out_distance = best_distance;
    }
    return out_name[0] != '\0';
}

static size_t token_column(const Parser *parser, const Token *token) {
    if (!parser || !token || token->type == TOKEN_ERROR || !token->start) {
        return 0;
    }
    const char *begin = parser->scanner.source;
    if (!begin) {
        return 0;
    }
    const char *cursor = token->start;
    if (cursor < begin) {
        return 0;
    }
    const char *line_start = cursor;
    while (line_start > begin && line_start[-1] != '\n') {
        line_start--;
    }
    return (size_t)(cursor - line_start) + 1u;
}

static void error_at(Parser *parser, const Token *token, const char *message) {
    if (parser->panic_mode) {
        return;
    }
    parser->panic_mode = true;
    parser->had_error = true;
    if (parser->error && parser->error->ok) {
        size_t column = token_column(parser, token);
        protoerror_set_with_column(parser->error, token->line, column, "%s", message);
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
    local->function_value = NULL;
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

static ProtoTypeTag parse_type_annotation(Parser *parser, int8_t *out_type_param_index) {
    if (out_type_param_index) {
        *out_type_param_index = -1;
    }
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
        case TOKEN_POINTER:
            parser_advance(parser);
            return PROTO_TYPE_PTR;
        case TOKEN_NONE:
            parser_advance(parser);
            return PROTO_TYPE_NONE;
        case TOKEN_IDENTIFIER: {
            Token identifier = parser->current;
            if (is_type_parameter(parser, &identifier)) {
                if (out_type_param_index) {
                    *out_type_param_index = resolve_type_parameter_index(parser, &identifier);
                }
                parser_advance(parser);
                return PROTO_TYPE_ANY;
            }
            error_at_current(parser, "Unknown type name");
            return PROTO_TYPE_ANY;
        }
        default:
            error_at_current(parser, "Expect type specifier");
            return PROTO_TYPE_ANY;
    }
}

static ProtoTypeTag parse_type_tag(Parser *parser) {
    return parse_type_annotation(parser, NULL);
}

static void emit_byte(Parser *parser, uint8_t byte) {
    protochunk_write(current_chunk(parser), byte, parser->previous.line);
}

static void emit_get_local(Parser *parser, uint8_t slot, size_t line) {
    protochunk_write(current_chunk(parser), PROTO_OP_GET_LOCAL, line);
    protochunk_write(current_chunk(parser), slot, line);
}

static void emit_set_local(Parser *parser, uint8_t slot, size_t line) {
    protochunk_write(current_chunk(parser), PROTO_OP_SET_LOCAL, line);
    protochunk_write(current_chunk(parser), slot, line);
}

static void emit_address_of_local(Parser *parser, uint8_t slot, bool is_const, size_t line) {
    protochunk_write(current_chunk(parser), PROTO_OP_ADDR_LOCAL, line);
    protochunk_write(current_chunk(parser), slot, line);
    protochunk_write(current_chunk(parser), is_const ? 1u : 0u, line);
}

static void emit_address_of_global(Parser *parser, uint16_t index, bool is_const, size_t line) {
    protochunk_write(current_chunk(parser), PROTO_OP_ADDR_GLOBAL, line);
    protochunk_write_u16(current_chunk(parser), index, line);
    protochunk_write(current_chunk(parser), is_const ? 1u : 0u, line);
}

static void emit_return(Parser *parser) {
    CompilerContext *context = current_context(parser);
    if (context && context->function && context->function->kind == PROTO_FUNC_INITIALIZER) {
        emit_get_local(parser, 0, parser->previous.line);
    } else {
        protochunk_write(current_chunk(parser), PROTO_OP_NULL, parser->previous.line);
    }
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
    ProtoTypeTag recorded[PROTOHACK_MAX_PARAMS] = {0};
    uint8_t recorded_count = 0;
    if (!check(parser, TOKEN_RIGHT_PAREN)) {
        do {
            parse_expression(parser);
            if (arg_count >= 255u) {
                error(parser, "Too many arguments");
            } else {
                arg_count++;
            }
            if (recorded_count < PROTOHACK_MAX_PARAMS) {
                recorded[recorded_count++] = parser->expression_type;
            }
        } while (match(parser, TOKEN_COMMA));
    }
    consume(parser, TOKEN_RIGHT_PAREN, "Expect ')' after arguments");
    parser->argument_count = recorded_count;
    if (recorded_count > 0) {
        memcpy(parser->argument_types, recorded, recorded_count * sizeof(ProtoTypeTag));
    }
    if (arg_count > 255u) {
        return 255u;
    }
    return (uint8_t)arg_count;
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

static bool tokens_equal(const Token *a, const Token *b) {
    if (!a || !b) {
        return false;
    }
    if (a->length != b->length) {
        return false;
    }
    if (a->length == 0) {
        return true;
    }
    return memcmp(a->start, b->start, a->length) == 0;
}

static bool identifier_matches_type_param(const Token *identifier, const Token *param) {
    if (!identifier || !param) {
        return false;
    }
    if (param->type != TOKEN_IDENTIFIER) {
        return false;
    }
    return tokens_equal(identifier, param);
}

static bool is_type_parameter(Parser *parser, const Token *identifier) {
    if (!parser || !identifier) {
        return false;
    }
    CompilerContext *context = parser->compiler;
    while (context) {
        for (uint8_t i = 0; i < context->type_param_count && i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
            if (identifier_matches_type_param(identifier, &context->type_params[i])) {
                return true;
            }
        }
        context = context->enclosing;
    }

    ClassCompiler *klass = parser->current_class;
    while (klass) {
        for (uint8_t i = 0; i < klass->type_param_count && i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
            if (identifier_matches_type_param(identifier, &klass->type_params[i])) {
                return true;
            }
        }
        klass = klass->enclosing;
    }

    return false;
}

static bool resolve_type_parameter_source(Parser *parser, const Token *identifier, int8_t *out_index, const CompilerContext **out_context, const ClassCompiler **out_class) {
    if (out_index) {
        *out_index = -1;
    }
    if (out_context) {
        *out_context = NULL;
    }
    if (out_class) {
        *out_class = NULL;
    }
    if (!parser || !identifier) {
        return false;
    }

    CompilerContext *context = parser->compiler;
    while (context) {
        for (uint8_t i = 0; i < context->type_param_count && i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
            if (identifier_matches_type_param(identifier, &context->type_params[i])) {
                if (out_index) {
                    *out_index = (int8_t)i;
                }
                if (out_context) {
                    *out_context = context;
                }
                return true;
            }
        }
        context = context->enclosing;
    }

    ClassCompiler *klass = parser->current_class;
    while (klass) {
        for (uint8_t i = 0; i < klass->type_param_count && i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
            if (identifier_matches_type_param(identifier, &klass->type_params[i])) {
                if (out_index) {
                    *out_index = (int8_t)i;
                }
                if (out_class) {
                    *out_class = klass;
                }
                return true;
            }
        }
        klass = klass->enclosing;
    }

    return false;
}

static int8_t resolve_type_parameter_index(Parser *parser, const Token *identifier) {
    int8_t index = -1;
    if (resolve_type_parameter_source(parser, identifier, &index, NULL, NULL)) {
        return index;
    }
    return -1;
}

static void parse_type_parameter_list(Parser *parser, const char *context_label, TypeParameterList *list) {
    if (!list) {
        return;
    }

    list->count = 0;
    const char *label = context_label ? context_label : "declaration";

    if (!match(parser, TOKEN_LESS)) {
        return;
    }

    if (match(parser, TOKEN_GREATER)) {
        return;
    }

    do {
        consume(parser, TOKEN_IDENTIFIER, "Expect type parameter name");
        Token param = parser->previous;

        bool skip_storage = false;
        if (list->count >= PROTOHACK_MAX_TYPE_PARAMS) {
            char message[128];
            snprintf(message, sizeof message, "Too many type parameters for %s (max %d)", label, PROTOHACK_MAX_TYPE_PARAMS);
            error(parser, message);
            skip_storage = true;
        }

        char buffer[PROTOHACK_MAX_IDENTIFIER + 1] = {0};
        bool buffer_ok = token_to_identifier(&param, buffer, sizeof buffer);
        if (!buffer_ok) {
            char message[128];
            snprintf(message, sizeof message, "Type parameter name is too long in %s", label);
            error(parser, message);
        }

        bool duplicate = false;
        if (buffer_ok) {
            for (uint8_t i = 0; i < list->count; ++i) {
                if (strcmp(list->names[i], buffer) == 0) {
                    duplicate = true;
                    char message[128];
                    snprintf(message, sizeof message, "Duplicate type parameter '%s' in %s", buffer, label);
                    error(parser, message);
                    break;
                }
            }
        }

        if (!skip_storage && buffer_ok && !duplicate && list->count < PROTOHACK_MAX_TYPE_PARAMS) {
            list->tokens[list->count] = param;
            memcpy(list->names[list->count], buffer, sizeof list->names[list->count]);
            list->count++;
        }
    } while (match(parser, TOKEN_COMMA));

    char end_message[128];
    snprintf(end_message, sizeof end_message, "Expect '>' after type parameters in %s", label);
    consume(parser, TOKEN_GREATER, end_message);
}

static bool parse_template_type_atom(Parser *parser, TemplateArg *out_arg) {
    if (!parser || !out_arg) {
        return false;
    }

    TemplateArg result = {0};
    result.param_index = -1;
    result.context = NULL;
    result.klass = NULL;
    switch (parser->current.type) {
        case TOKEN_NUMERIC:
            parser_advance(parser);
            result.tag = PROTO_TYPE_NUM;
            strncpy(result.label, proto_type_tag_name(PROTO_TYPE_NUM), sizeof result.label - 1);
            result.label[sizeof result.label - 1] = '\0';
            break;
        case TOKEN_FLAG:
            parser_advance(parser);
            result.tag = PROTO_TYPE_FLAG;
            strncpy(result.label, proto_type_tag_name(PROTO_TYPE_FLAG), sizeof result.label - 1);
            result.label[sizeof result.label - 1] = '\0';
            break;
        case TOKEN_TEXT:
            parser_advance(parser);
            result.tag = PROTO_TYPE_TEXT;
            strncpy(result.label, proto_type_tag_name(PROTO_TYPE_TEXT), sizeof result.label - 1);
            result.label[sizeof result.label - 1] = '\0';
            break;
        case TOKEN_RAW:
            parser_advance(parser);
            result.tag = PROTO_TYPE_RAW;
            strncpy(result.label, proto_type_tag_name(PROTO_TYPE_RAW), sizeof result.label - 1);
            result.label[sizeof result.label - 1] = '\0';
            break;
        case TOKEN_POINTER:
            parser_advance(parser);
            result.tag = PROTO_TYPE_PTR;
            strncpy(result.label, proto_type_tag_name(PROTO_TYPE_PTR), sizeof result.label - 1);
            result.label[sizeof result.label - 1] = '\0';
            break;
        case TOKEN_NONE:
            parser_advance(parser);
            result.tag = PROTO_TYPE_NONE;
            strncpy(result.label, proto_type_tag_name(PROTO_TYPE_NONE), sizeof result.label - 1);
            result.label[sizeof result.label - 1] = '\0';
            break;
        case TOKEN_IDENTIFIER: {
            Token identifier = parser->current;
            char buffer[PROTOHACK_MAX_IDENTIFIER + 1] = {0};
            if (!token_to_identifier(&identifier, buffer, sizeof buffer)) {
                return false;
            }

            const CompilerContext *binding_context = NULL;
            const ClassCompiler *binding_class = NULL;
            int8_t binding_index = -1;
            bool resolved = resolve_type_parameter_source(parser, &identifier, &binding_index, &binding_context, &binding_class);

            parser_advance(parser);
            result.tag = PROTO_TYPE_ANY;
            result.param_index = resolved ? binding_index : -1;
            result.context = resolved ? binding_context : NULL;
            result.klass = resolved ? binding_class : NULL;
            result.unresolved = !resolved;
            strncpy(result.label, buffer, sizeof result.label - 1);
            result.label[sizeof result.label - 1] = '\0';
            break;
        }
        default:
            return false;
    }

    *out_arg = result;
    return true;
}

static bool try_parse_template_arguments(Parser *parser, TemplateArgList *out_args) {
    if (!parser || parser->current.type != TOKEN_LESS) {
        return false;
    }

    Scanner backup_scanner = parser->scanner;
    Token backup_current = parser->current;
    Token backup_previous = parser->previous;
    bool backup_had_error = parser->had_error;
    bool backup_panic = parser->panic_mode;

    parser_advance(parser);
    TemplateArgList parsed = {0};

    if (parser->current.type == TOKEN_GREATER) {
        parser_advance(parser);
    } else {
        do {
            if (parsed.count >= PROTOHACK_MAX_TYPE_PARAMS) {
                goto parse_fail;
            }
            TemplateArg arg = {0};
            if (!parse_template_type_atom(parser, &arg)) {
                goto parse_fail;
            }
            parsed.args[parsed.count++] = arg;
        } while (match(parser, TOKEN_COMMA));

        if (!match(parser, TOKEN_GREATER)) {
            goto parse_fail;
        }
    }

    if (out_args) {
        *out_args = parsed;
    }
    return true;

parse_fail:
    parser->scanner = backup_scanner;
    parser->current = backup_current;
    parser->previous = backup_previous;
    parser->had_error = backup_had_error;
    parser->panic_mode = backup_panic;
    return false;
}

static FunctionTemplateEntry *find_function_template(Parser *parser, const char *name) {
    if (!parser || !name) {
        return NULL;
    }
    for (size_t i = 0; i < parser->generics.function_template_count; ++i) {
        FunctionTemplateEntry *entry = &parser->generics.function_templates[i];
        if (entry->name[0] != '\0' && strcmp(entry->name, name) == 0) {
            return entry;
        }
    }
    return NULL;
}

static bool register_function_template(Parser *parser, const char *name, ProtoFunction *function, uint8_t type_param_count) {
    if (!parser || !name || !function) {
        return false;
    }

    FunctionTemplateEntry *existing = find_function_template(parser, name);
    if (existing) {
        existing->function = function;
        existing->type_param_count = type_param_count;
        return true;
    }

    if (parser->generics.function_template_count >= PROTOHACK_MAX_FUNCTION_TEMPLATES) {
        return false;
    }

    FunctionTemplateEntry *entry = &parser->generics.function_templates[parser->generics.function_template_count++];
    strncpy(entry->name, name, sizeof entry->name - 1);
    entry->name[sizeof entry->name - 1] = '\0';
    entry->function = function;
    entry->type_param_count = type_param_count;
    return true;
}

static bool extension_binding_is_concrete(const ProtoTypeBinding *binding) {
    if (!binding) {
        return false;
    }
    if (binding->param >= 0) {
        return false;
    }
    return binding->tag != PROTO_TYPE_ANY;
}

static void raise_extension_error(Parser *parser, const Token *target_token, const char *message) {
    Token previous = parser->previous;
    if (target_token != NULL) {
        parser->previous = *target_token;
    }
    error(parser, message);
    parser->previous = previous;
}

static bool validate_extension_contract(Parser *parser, const Token *target_token, ProtoExtensionDecl *decl) {
    if (!decl) {
        return false;
    }

    bool ok = true;

    if (decl->target_kind == PROTO_EXTENSION_TARGET_CRAFT) {
        ProtoFunction *craft = NULL;
        ProtoChunk *global_chunk = parser ? parser->chunk : NULL;
        if (global_chunk != NULL) {
            int global_index = protochunk_find_global(global_chunk, decl->target.name);
            if (global_index >= 0 && parser->globals.defined[global_index]) {
                craft = parser->globals.functions[global_index];
            }
        }
        if (craft == NULL) {
            FunctionSpecializationEntry *specialization = find_function_specialization(parser, decl->target.name);
            if (specialization != NULL) {
                craft = specialization->function;
            }
        }
        if (craft == NULL) {
            FunctionTemplateEntry *tpl = find_function_template(parser, decl->target.name);
            if (tpl != NULL) {
                craft = tpl->function;
            }
        }

        if (craft == NULL || craft->kind != PROTO_FUNC_CRAFT) {
            raise_extension_error(parser, target_token, "Craft extension target must be a declared craft function");
            return false;
        }

        uint8_t expected = craft->type_param_count;
        uint8_t provided = decl->target.bindings.count;

        if (expected == 0) {
            if (provided > 0) {
                raise_extension_error(parser, target_token, "Craft does not accept type arguments");
                ok = false;
            }
        } else {
            if (provided == 0) {
                char message[128];
                snprintf(message, sizeof(message), "Craft '%s' requires %u type argument%s", decl->target.name, expected, expected == 1 ? "" : "s");
                raise_extension_error(parser, target_token, message);
                ok = false;
            } else if (provided != expected) {
                char message[128];
                snprintf(message, sizeof(message), "Craft '%s' expects %u type argument%s but %u provided", decl->target.name, expected, expected == 1 ? "" : "s", provided);
                raise_extension_error(parser, target_token, message);
                ok = false;
            }

            for (uint8_t i = 0; ok && i < provided; ++i) {
                if (!extension_binding_is_concrete(&decl->target.bindings.entries[i])) {
                    char message[160];
                    snprintf(message, sizeof(message), "Extension must specialize craft '%s' with concrete type arguments", decl->target.name);
                    raise_extension_error(parser, target_token, message);
                    ok = false;
                }
            }
        }
    }

    for (uint8_t i = 0; i < decl->trait_count; ++i) {
        const ProtoExtensionTypeSpec *trait = &decl->traits[i];
        for (uint8_t j = 0; j < trait->bindings.count; ++j) {
            if (!extension_binding_is_concrete(&trait->bindings.entries[j])) {
                char message[160];
                snprintf(message, sizeof(message), "Trait '%s' in extension requires concrete type arguments", trait->name);
                raise_extension_error(parser, target_token, message);
                return false;
            }
        }
    }

    return ok;
}

static const ProtoFunction *resolve_extension_craft_template(Parser *parser, const ProtoExtensionDecl *decl) {
    if (!parser || !decl) {
        return NULL;
    }

    const char *name = decl->target.name;
    if (!name || name[0] == '\0') {
        return NULL;
    }

    ProtoChunk *chunk = parser->chunk;
    if (chunk) {
        int global_index = protochunk_find_global(chunk, name);
        if (global_index >= 0 && parser->globals.defined[global_index]) {
            ProtoFunction *fn = parser->globals.functions[global_index];
            if (fn && fn->kind == PROTO_FUNC_CRAFT) {
                return fn;
            }
        }
    }

    FunctionTemplateEntry *tpl = find_function_template(parser, name);
    if (tpl && tpl->function && tpl->function->kind == PROTO_FUNC_CRAFT) {
        return tpl->function;
    }

    FunctionSpecializationEntry *spec = find_function_specialization(parser, name);
    if (spec && spec->function && spec->function->kind == PROTO_FUNC_CRAFT) {
        return spec->function->template_origin ? spec->function->template_origin : spec->function;
    }

    return NULL;
}

static ProtoTypeTag resolve_extension_specialized_type(const ProtoFunction *template_function,
                                                       const ProtoTypeBindingSet *bindings,
                                                       ProtoTypeTag default_tag,
                                                       int8_t binding_index) {
    if (!bindings) {
        return default_tag;
    }

    if (binding_index >= 0 && (uint8_t)binding_index < bindings->count) {
        const ProtoTypeBinding *binding = &bindings->entries[(uint8_t)binding_index];
        if (binding->tag != PROTO_TYPE_ANY && binding->param < 0) {
            return binding->tag;
        }
    }

    (void)template_function;
    return default_tag;
}

static FunctionSpecializationEntry *find_function_specialization(Parser *parser, const char *name) {
    if (!parser || !name) {
        return NULL;
    }
    for (size_t i = 0; i < parser->generics.function_specialization_count; ++i) {
        FunctionSpecializationEntry *entry = &parser->generics.function_specializations[i];
        if (entry->name[0] != '\0' && strcmp(entry->name, name) == 0) {
            return entry;
        }
    }
    return NULL;
}

static bool add_function_specialization(Parser *parser, const char *name, uint16_t constant_index, ProtoFunction *function) {
    if (!parser || !name) {
        return false;
    }
    if (parser->generics.function_specialization_count >= PROTOHACK_MAX_FUNCTION_SPECIALIZATIONS) {
        return false;
    }
    FunctionSpecializationEntry *entry = &parser->generics.function_specializations[parser->generics.function_specialization_count++];
    strncpy(entry->name, name, sizeof entry->name - 1);
    entry->name[sizeof entry->name - 1] = '\0';
    entry->constant_index = constant_index;
    entry->function = function;
    return true;
}

static bool ensure_function_specialization(Parser *parser, const Token *name_token, const char *base_name, const TemplateArgList *args, uint16_t *out_constant_index, ProtoFunction **out_function) {
    if (!parser || !name_token || !base_name || !args || !out_constant_index) {
        return false;
    }

    if (out_function) {
        *out_function = NULL;
    }

    FunctionTemplateEntry *template_entry = find_function_template(parser, base_name);
    if (!template_entry) {
        char message[256];
        snprintf(message, sizeof message, "'%s' is not a generic craft", base_name);
        error(parser, message);
        return false;
    }

    if (template_entry->type_param_count != args->count) {
        char message[256];
        snprintf(message, sizeof message, "Craft '%s' expects %u type argument(s)", base_name, template_entry->type_param_count);
        error(parser, message);
        return false;
    }

    TemplateArgList resolved_args = *args;
    ProtoTypeBindingSet binding_set;
    uint8_t arg_count = args->count;
    if (arg_count > PROTOHACK_MAX_TYPE_PARAMS) {
        arg_count = PROTOHACK_MAX_TYPE_PARAMS;
    }
    binding_set.count = arg_count;
    for (uint8_t i = 0; i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
        binding_set.entries[i].tag = PROTO_TYPE_ANY;
        binding_set.entries[i].param = -1;
    }

    for (uint8_t i = 0; i < arg_count; ++i) {
        ProtoTypeBinding binding = resolve_template_argument_binding(&args->args[i]);
        binding_set.entries[i] = binding;

        ProtoTypeTag effective_tag = binding.tag;
        if (effective_tag == PROTO_TYPE_ANY) {
            effective_tag = args->args[i].tag;
        }
        resolved_args.args[i].tag = effective_tag;
        if (effective_tag != PROTO_TYPE_ANY) {
            const char *label = proto_type_tag_name(effective_tag);
            if (label) {
                strncpy(resolved_args.args[i].label, label, sizeof resolved_args.args[i].label - 1);
                resolved_args.args[i].label[sizeof resolved_args.args[i].label - 1] = '\0';
            }
        }
    }

    for (uint8_t i = 0; i < arg_count; ++i) {
        const ProtoTypeBinding *binding = &binding_set.entries[i];
        const TemplateArg *original_arg = &args->args[i];
        bool unresolved_identifier = original_arg->unresolved;
        bool missing_binding = (!unresolved_identifier && binding->tag == PROTO_TYPE_ANY && binding->param < 0);
        if (unresolved_identifier || missing_binding) {
            char message[256];
            const char *label = original_arg->label[0] != '\0' ? original_arg->label : proto_type_tag_name(original_arg->tag);
            if (!label) {
                label = "unknown";
            }
            if (unresolved_identifier) {
                snprintf(message, sizeof message, "Unknown type argument '%s' supplied to craft '%s'", label, base_name);
            } else {
                const char *param_name = NULL;
                if (template_entry->function && i < template_entry->function->type_param_count) {
                    param_name = template_entry->function->type_params[i];
                }
                if (param_name && param_name[0] != '\0') {
                    snprintf(message, sizeof message, "Unable to resolve binding for type parameter '%s' when instantiating craft '%s'", param_name, base_name);
                } else {
                    snprintf(message, sizeof message, "Unable to resolve type argument %u when instantiating craft '%s'", (unsigned)(i + 1), base_name);
                }
            }
            Token saved_previous = parser->previous;
            parser->previous = *name_token;
            error(parser, message);
            parser->previous = saved_previous;
            return false;
        }
    }

    const char *label_ptrs[PROTOHACK_MAX_TYPE_PARAMS] = {0};
    for (uint8_t i = 0; i < arg_count; ++i) {
        label_ptrs[i] = resolved_args.args[i].label[0] != '\0' ? resolved_args.args[i].label : NULL;
    }

    char formatted[PROTOHACK_MAX_TEMPLATE_NAME];
    if (!proto_function_format_specialization_name(base_name,
                                                   template_entry->function,
                                                   &binding_set,
                                                   label_ptrs,
                                                   arg_count,
                                                   formatted,
                                                   sizeof formatted)) {
        error(parser, "Failed to format generic specialization name");
        return false;
    }

    FunctionSpecializationEntry *existing = find_function_specialization(parser, formatted);
    if (existing) {
        *out_constant_index = existing->constant_index;
        if (out_function) {
            *out_function = existing->function;
        }
        return true;
    }

    ProtoFunction *instance = proto_function_copy(template_entry->function);
    if (!instance) {
        error(parser, "Failed to instantiate generic craft");
        return false;
    }
    instance->template_origin = template_entry->function;
    if (!proto_function_set_name(instance, formatted)) {
        proto_function_free(instance);
        error(parser, "Failed to assign specialization name");
        return false;
    }

    ProtoTypeTag argument_tags[PROTOHACK_MAX_TYPE_PARAMS];
    for (uint8_t i = 0; i < arg_count; ++i) {
        ProtoTypeTag tag = binding_set.entries[i].tag;
        if (tag == PROTO_TYPE_ANY) {
            tag = resolved_args.args[i].tag;
        }
        argument_tags[i] = tag;
    }
    if (!proto_function_set_type_arguments(instance, argument_tags, arg_count)) {
        proto_function_free(instance);
        error(parser, "Failed to record specialization type arguments");
        return false;
    }

    instance->bindings = binding_set;

    for (uint8_t i = 0; i < instance->arity && i < PROTOHACK_MAX_PARAMS; ++i) {
        int8_t binding = instance->param_type_params[i];
        if (binding >= 0 && binding < (int8_t)arg_count) {
            instance->param_types[i] = argument_tags[binding];
        }
    }
    if (instance->return_type_param >= 0 && instance->return_type_param < (int8_t)arg_count) {
        instance->return_type = argument_tags[instance->return_type_param];
    }

    Token saved_previous = parser->previous;
    parser->previous = *name_token;
    uint16_t index = make_constant(parser, proto_value_function(instance));
    parser->previous = saved_previous;

    if (!add_function_specialization(parser, formatted, index, instance)) {
        error(parser, "Too many generic specializations in module");
        return false;
    }

    if (out_function) {
        *out_function = instance;
    }

    *out_constant_index = index;
    return true;
}

static void emit_constant_index(Parser *parser, uint16_t index, size_t line) {
    protochunk_write(current_chunk(parser), PROTO_OP_CONSTANT, line);
    protochunk_write_u16(current_chunk(parser), index, line);
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
        char message[256];
        char suggestion[PROTOHACK_MAX_IDENTIFIER + 1];
        size_t distance = SUGGESTION_NO_MATCH;
        bool has_suggestion = suggest_identifier(parser, identifier, suggestion, sizeof suggestion, &distance);
        size_t threshold = suggestion_threshold(strlen(identifier));
        if (has_suggestion && distance != SUGGESTION_NO_MATCH && distance <= threshold) {
            snprintf(message, sizeof message, "Undefined global '%s'. Did you mean '%s'?", identifier, suggestion);
        } else {
            snprintf(message, sizeof message, "Undefined global '%s'", identifier);
        }
        error(parser, message);
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
        char message[256];
        char suggestion[PROTOHACK_MAX_IDENTIFIER + 1];
        size_t distance = SUGGESTION_NO_MATCH;
        bool has_suggestion = suggest_native_identifier(identifier, suggestion, sizeof suggestion, &distance);
        size_t threshold = suggestion_threshold(strlen(identifier));
        if (has_suggestion && distance != SUGGESTION_NO_MATCH && distance <= threshold) {
            snprintf(message, sizeof message, "Unknown native function '%s'. Did you mean '%s'?", identifier, suggestion);
        } else {
            snprintf(message, sizeof message, "Unknown native function '%s'", identifier);
        }
        error(parser, message);
        return;
    }

    const ProtoNativeEntry *entry = protonative_resolve(identifier);
    if (!entry) {
        char message[256];
        char suggestion[PROTOHACK_MAX_IDENTIFIER + 1];
        size_t distance = SUGGESTION_NO_MATCH;
        bool has_suggestion = suggest_native_identifier(identifier, suggestion, sizeof suggestion, &distance);
        size_t threshold = suggestion_threshold(strlen(identifier));
        if (has_suggestion && distance != SUGGESTION_NO_MATCH && distance <= threshold) {
            snprintf(message, sizeof message, "Unknown native function '%s'. Did you mean '%s'?", identifier, suggestion);
        } else {
            snprintf(message, sizeof message, "Unknown native function '%s'", identifier);
        }
        error(parser, message);
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
    ProtoFunction *target_function = NULL;
    ProtoTypeTag return_type = PROTO_TYPE_ANY;

    if (local_slot >= 0) {
        emit_get_local(parser, (uint8_t)local_slot, name.line);
        CompilerContext *context = current_context(parser);
        if (context && local_slot < context->local_count && local_slot >= 0) {
            Local *local = &context->locals[local_slot];
            if (local->function_value) {
                target_function = local->function_value;
                return_type = target_function->return_type;
            }
        }
    } else {
        int global_index = resolve_global(parser, name);
        if (global_index < 0) {
            return;
        }
        emit_get_global(parser, &name, (uint16_t)global_index);
        if (global_index >= 0 && global_index < PROTOHACK_MAX_GLOBALS) {
            target_function = parser->globals.functions[global_index];
            if (target_function) {
                return_type = target_function->return_type;
            }
        }
    }
    if (!paren_consumed) {
        parser_advance(parser);
    }
    uint8_t arg_count = parse_call_arguments(parser);
    if (target_function) {
        validate_call_arguments(parser, &name, target_function, arg_count);
    }
    emit_byte(parser, PROTO_OP_CALL);
    emit_byte(parser, arg_count);
    parser_set_expression(parser, return_type, NULL);
}

static void validate_call_arguments(Parser *parser, const Token *name_token, const ProtoFunction *function, uint8_t provided_count) {
    if (!parser || !function) {
        return;
    }

    uint8_t expected = function->arity;
    if (provided_count != expected) {
        char message[256];
        if (name_token && name_token->length > 0) {
            snprintf(message,
                     sizeof message,
                     "'%.*s' expects %u argument%s but received %u",
                     (int)name_token->length,
                     name_token->start,
                     expected,
                     expected == 1 ? "" : "s",
                     provided_count);
        } else {
            snprintf(message,
                     sizeof message,
                     "Function expects %u argument%s but received %u",
                     expected,
                     expected == 1 ? "" : "s",
                     provided_count);
        }
        error(parser, message);
        return;
    }

    uint8_t check_count = parser->argument_count;
    if (check_count > expected) {
        check_count = expected;
    }

    for (uint8_t i = 0; i < check_count; ++i) {
        ProtoTypeTag expected_tag = function->param_types[i];
        ProtoTypeTag actual_tag = parser->argument_types[i];
        if (expected_tag == PROTO_TYPE_ANY || actual_tag == PROTO_TYPE_ANY) {
            continue;
        }
        if (expected_tag == actual_tag) {
            continue;
        }
        const char *expected_name = proto_type_tag_name(expected_tag);
        const char *actual_name = proto_type_tag_name(actual_tag);
        char message[256];
        if (name_token && name_token->length > 0) {
            snprintf(message,
                     sizeof message,
                     "Argument %u of '%.*s' expects %s but received %s",
                     (unsigned)(i + 1),
                     (int)name_token->length,
                     name_token->start,
                     expected_name,
                     actual_name);
        } else {
            snprintf(message,
                     sizeof message,
                     "Argument %u expects %s but received %s",
                     (unsigned)(i + 1),
                     expected_name,
                     actual_name);
        }
        error(parser, message);
        return;
    }
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

static void parse_this(Parser *parser, bool can_assign) {
    (void)can_assign;
    if (!parser->current_class) {
        error(parser, "'this' is only valid inside class methods");
        return;
    }
    emit_get_local(parser, 0, parser->previous.line);
}

static void parse_dot(Parser *parser, bool can_assign) {
    consume(parser, TOKEN_IDENTIFIER, "Expect property name after '.'");
    Token name = parser->previous;

    Token saved_previous = parser->previous;
    parser->previous = name;
    uint16_t name_constant = make_constant(parser, proto_value_string(name.start, name.length));
    parser->previous = saved_previous;

    if (can_assign && match(parser, TOKEN_EQUAL)) {
        parse_expression(parser);
        protochunk_write(current_chunk(parser), PROTO_OP_SET_PROPERTY, name.line);
        protochunk_write_u16(current_chunk(parser), name_constant, name.line);
    } else if (match(parser, TOKEN_LEFT_PAREN)) {
        protochunk_write(current_chunk(parser), PROTO_OP_GET_PROPERTY, name.line);
        protochunk_write_u16(current_chunk(parser), name_constant, name.line);
        uint8_t arg_count = parse_call_arguments(parser);
        emit_byte(parser, PROTO_OP_CALL);
        emit_byte(parser, arg_count);
    } else {
        protochunk_write(current_chunk(parser), PROTO_OP_GET_PROPERTY, name.line);
        protochunk_write_u16(current_chunk(parser), name_constant, name.line);
    }
}

static void parse_address(Parser *parser, bool can_assign) {
    (void)can_assign;
    consume(parser, TOKEN_IDENTIFIER, "Expect identifier after '&'");
    Token name = parser->previous;
    CompilerContext *context = current_context(parser);
    int local_slot = context ? resolve_local(parser, name) : -1;
    if (local_slot >= 0) {
        bool is_const = context->locals[local_slot].is_const;
        emit_address_of_local(parser, (uint8_t)local_slot, is_const, name.line);
        parser_set_expression(parser, PROTO_TYPE_PTR, NULL);
        return;
    }

    int global_index = resolve_global(parser, name);
    if (global_index < 0) {
        return;
    }
    bool is_const = parser->globals.is_const[global_index];
    emit_address_of_global(parser, (uint16_t)global_index, is_const, name.line);
    parser_set_expression(parser, PROTO_TYPE_PTR, NULL);
}

static void parse_pointer_deref(Parser *parser, bool can_assign) {
    Token star = parser->previous;
    parse_precedence(parser, PREC_UNARY);
    if (can_assign && match(parser, TOKEN_EQUAL)) {
        parse_expression(parser);
        protochunk_write(current_chunk(parser), PROTO_OP_PTR_STORE, star.line);
    } else {
        protochunk_write(current_chunk(parser), PROTO_OP_PTR_LOAD, star.line);
    }
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
            parser_set_expression(parser, PROTO_TYPE_FLAG, NULL);
            break;
        case TOKEN_MINUS:
            emit_byte(parser, PROTO_OP_NEGATE);
            if (parser->expression_type != PROTO_TYPE_ANY) {
                parser_set_expression(parser, PROTO_TYPE_NUM, NULL);
            }
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

    switch (operator_type) {
        case TOKEN_PLUS:
        case TOKEN_MINUS:
        case TOKEN_STAR:
        case TOKEN_SLASH:
            parser_set_expression(parser, PROTO_TYPE_NUM, NULL);
            break;
        case TOKEN_EQUAL_EQUAL:
        case TOKEN_BANG_EQUAL:
        case TOKEN_GREATER:
        case TOKEN_GREATER_EQUAL:
        case TOKEN_LESS:
        case TOKEN_LESS_EQUAL:
            parser_set_expression(parser, PROTO_TYPE_FLAG, NULL);
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
            parser_set_expression(parser, PROTO_TYPE_FLAG, NULL);
            break;
        case TOKEN_FALSE:
            emit_byte(parser, PROTO_OP_FALSE);
            parser_set_expression(parser, PROTO_TYPE_FLAG, NULL);
            break;
        case TOKEN_NULL:
            emit_byte(parser, PROTO_OP_NULL);
            parser_set_expression(parser, PROTO_TYPE_NONE, NULL);
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
    parser_set_expression(parser, PROTO_TYPE_NUM, NULL);
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
    parser_set_expression(parser, PROTO_TYPE_TEXT, NULL);
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
            if (local) {
                local->function_value = parser->recent_function_value;
            }
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
        parser->globals.functions[global_index] = parser->recent_function_value;
        emit_set_global(parser, &name, (uint16_t)global_index);
        return;
    }

    TemplateArgList template_args = {0};
    bool has_template = try_parse_template_arguments(parser, &template_args);
    if (has_template) {
        if (local_slot >= 0) {
            error(parser, "Generic specialization cannot target local identifiers");
            return;
        }
        char identifier[PROTOHACK_MAX_IDENTIFIER + 1];
        if (!token_to_identifier(&name, identifier, sizeof identifier)) {
            error(parser, "Identifier is too long");
            return;
        }
        uint16_t constant_index = 0;
        ProtoFunction *specialized_function = NULL;
        if (!ensure_function_specialization(parser, &name, identifier, &template_args, &constant_index, &specialized_function)) {
            return;
        }
        emit_constant_index(parser, constant_index, name.line);
        parser_set_expression(parser, PROTO_TYPE_ANY, specialized_function);
        if (parser->current.type == TOKEN_LEFT_PAREN) {
            parser_advance(parser);
            uint8_t arg_count = parse_call_arguments(parser);
            if (specialized_function) {
                validate_call_arguments(parser, &name, specialized_function, arg_count);
                parser_set_expression(parser, specialized_function->return_type, NULL);
            } else {
                parser_reset_expression(parser);
            }
            emit_byte(parser, PROTO_OP_CALL);
            emit_byte(parser, arg_count);
            parser->recent_function_value = NULL;
        }
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
        ProtoTypeTag local_type = local ? local->type_tag : PROTO_TYPE_ANY;
        ProtoFunction *local_function = local ? local->function_value : NULL;
        parser_set_expression(parser, local_type, local_function);
        return;
    }

    int index = resolve_global(parser, name);
    if (index < 0) {
        return;
    }
    emit_get_global(parser, &name, (uint16_t)index);
    ProtoTypeTag global_type = parser->globals.type_tags[index];
    ProtoFunction *global_function = parser->globals.functions[index];
    parser_set_expression(parser, global_type, global_function);
}

static ParseRule rules[] = {
    [TOKEN_LEFT_PAREN] = {parse_grouping, NULL, PREC_NONE},
    [TOKEN_RIGHT_PAREN] = {NULL, NULL, PREC_NONE},
    [TOKEN_LEFT_BRACE] = {NULL, NULL, PREC_NONE},
    [TOKEN_RIGHT_BRACE] = {NULL, NULL, PREC_NONE},
    [TOKEN_COMMA] = {NULL, NULL, PREC_NONE},
    [TOKEN_DOT] = {NULL, parse_dot, PREC_PRIMARY},
    [TOKEN_AMPERSAND] = {parse_address, NULL, PREC_UNARY},
    [TOKEN_MINUS] = {parse_unary, parse_binary, PREC_TERM},
    [TOKEN_PLUS] = {NULL, parse_binary, PREC_TERM},
    [TOKEN_SEMICOLON] = {NULL, NULL, PREC_NONE},
    [TOKEN_SLASH] = {NULL, parse_binary, PREC_FACTOR},
    [TOKEN_STAR] = {parse_pointer_deref, parse_binary, PREC_FACTOR},
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
    [TOKEN_EXTEND] = {NULL, NULL, PREC_NONE},
    [TOKEN_TRUE] = {parse_literal, NULL, PREC_NONE},
    [TOKEN_THIS] = {parse_this, NULL, PREC_NONE},
    [TOKEN_WHILE] = {NULL, NULL, PREC_NONE},
    [TOKEN_WITH] = {NULL, NULL, PREC_NONE},
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
    parser_reset_expression(parser);
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
            case TOKEN_CLASS:
            case TOKEN_CRAFT:
            case TOKEN_EXTEND:
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

static void method_declaration(Parser *parser, Token class_name) {
    (void)class_name;
    consume(parser, TOKEN_IDENTIFIER, "Expect method name");
    Token method_name = parser->previous;

    char identifier[PROTOHACK_MAX_IDENTIFIER + 1];
    if (!token_to_identifier(&method_name, identifier, sizeof identifier)) {
        error(parser, "Identifier is too long");
        return;
    }

    bool is_initializer = (method_name.length == 4 && memcmp(method_name.start, "init", 4) == 0);
    ProtoFunctionKind kind = is_initializer ? PROTO_FUNC_INITIALIZER : PROTO_FUNC_METHOD;
    ProtoFunction *function = proto_function_new(kind, identifier);

    const char *type_param_names[PROTOHACK_MAX_TYPE_PARAMS] = {0};
    uint8_t class_type_param_count = 0;
    if (parser->current_class) {
        class_type_param_count = parser->current_class->type_param_count;
        for (uint8_t i = 0; i < class_type_param_count && i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
            type_param_names[i] = parser->current_class->type_param_names[i];
        }
    }
    if (!proto_function_set_type_params(function, type_param_names, class_type_param_count)) {
        error(parser, "Failed to record type parameters for method");
    }

    CompilerContext context = {0};
    context.function = function;
    context.chunk = &function->chunk;
    context.local_count = 0;
    context.scope_depth = 0;
    context.expected_return = PROTO_TYPE_NONE;
    context.type_param_count = class_type_param_count;
    for (uint8_t i = 0; i < class_type_param_count && i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
        context.type_params[i] = parser->current_class->type_params[i];
    }
    context.enclosing = parser->compiler;
    compiler_context_reset_bindings(&context);

    Token synthetic = {.type = TOKEN_THIS, .start = "this", .length = 4, .line = method_name.line};
    context.locals[context.local_count++] = (Local){synthetic, 0, true, PROTO_TYPE_ANY, NULL};

    CompilerContext *previous = parser->compiler;
    parser->compiler = &context;

    consume(parser, TOKEN_LEFT_PAREN, "Expect '(' after method name");
    if (!check(parser, TOKEN_RIGHT_PAREN)) {
        do {
            if (function->arity >= PROTOHACK_MAX_PARAMS) {
                error(parser, "Too many parameters");
            }
            consume(parser, TOKEN_IDENTIFIER, "Expect parameter name");
            Token param_name = parser->previous;
            ProtoTypeTag param_type = PROTO_TYPE_ANY;
            int8_t param_binding = -1;
            if (match(parser, TOKEN_AS)) {
                param_type = parse_type_annotation(parser, &param_binding);
            }
            if (function->arity < PROTOHACK_MAX_PARAMS) {
                function->param_types[function->arity] = param_type;
                function->param_type_params[function->arity] = param_binding;
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
    int8_t return_binding = -1;
    if (match(parser, TOKEN_GIVES)) {
        return_type = parse_type_annotation(parser, &return_binding);
    }
    if (kind == PROTO_FUNC_INITIALIZER && return_type != PROTO_TYPE_NONE) {
        error(parser, "Initializers cannot declare return types");
        return_type = PROTO_TYPE_NONE;
    }
    function->return_type = return_type;
    function->return_type_param = return_binding;
    context.expected_return = return_type;

    parse_function_body(parser, function);
    emit_return(parser);

    sync_function_globals(parser, &function->chunk);

    parser->compiler = previous;

    Token saved = parser->previous;
    parser->previous = method_name;
    emit_constant(parser, proto_value_function(function));
    parser->previous = saved;

    parser->previous = method_name;
    uint16_t name_constant = make_constant(parser, proto_value_string(method_name.start, method_name.length));
    parser->previous = saved;

    protochunk_write(current_chunk(parser), PROTO_OP_METHOD, method_name.line);
    protochunk_write_u16(current_chunk(parser), name_constant, method_name.line);
}

static void class_declaration(Parser *parser) {
    CompilerContext *enclosing = current_context(parser);
    if (enclosing && enclosing != &parser->root) {
        error(parser, "Nested 'class' declarations are not supported yet");
        return;
    }

    consume(parser, TOKEN_IDENTIFIER, "Expect class name after 'class'");
    Token class_name = parser->previous;

    char identifier[PROTOHACK_MAX_IDENTIFIER + 1];
    if (!token_to_identifier(&class_name, identifier, sizeof identifier)) {
        error(parser, "Identifier is too long");
        return;
    }

    TypeParameterList type_params = {0};
    parse_type_parameter_list(parser, identifier, &type_params);

    int global_index = declare_global(parser, class_name, true);
    if (global_index < 0) {
        return;
    }

    parser->globals.defined[global_index] = true;
    parser->globals.is_const[global_index] = true;

    Token saved = parser->previous;
    parser->previous = class_name;
    uint16_t name_constant = make_constant(parser, proto_value_string(class_name.start, class_name.length));
    parser->previous = saved;

    protochunk_write(current_chunk(parser), PROTO_OP_CLASS, class_name.line);
    protochunk_write_u16(current_chunk(parser), name_constant, class_name.line);
    emit_set_global(parser, &class_name, (uint16_t)global_index);

    ClassCompiler class_compiler = {0};
    class_compiler.name = class_name;
    class_compiler.type_param_count = type_params.count;
    for (uint8_t i = 0; i < type_params.count && i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
        class_compiler.type_params[i] = type_params.tokens[i];
        memcpy(class_compiler.type_param_names[i], type_params.names[i], sizeof class_compiler.type_param_names[i]);
    }
    class_compiler_reset_bindings(&class_compiler);
    class_compiler.enclosing = parser->current_class;
    parser->current_class = &class_compiler;

    consume(parser, TOKEN_LEFT_BRACE, "Expect '{' before class body");
    while (!check(parser, TOKEN_RIGHT_BRACE) && !check(parser, TOKEN_EOF)) {
        method_declaration(parser, class_name);
    }
    consume(parser, TOKEN_RIGHT_BRACE, "Expect '}' after class body");

    protochunk_write(current_chunk(parser), PROTO_OP_POP, class_name.line);

    parser->current_class = class_compiler.enclosing;
}

static void extend_declaration(Parser *parser) {
    if (!parser) {
        return;
    }

    Token keyword = parser->previous;
    if (match(parser, TOKEN_CRAFT)) {
        extend_craft(parser, keyword);
        return;
    }

    if (match(parser, TOKEN_CLASS)) {
        error(parser, "Class extensions are not implemented yet");
    } else {
        error(parser, "Expect 'craft' or 'class' after 'extend'");
    }

    if (match(parser, TOKEN_LEFT_BRACE)) {
        int depth = 1;
        while (depth > 0 && !check(parser, TOKEN_EOF)) {
            if (match(parser, TOKEN_LEFT_BRACE)) {
                depth++;
            } else if (match(parser, TOKEN_RIGHT_BRACE)) {
                depth--;
            } else {
                parser_advance(parser);
            }
        }
    }
}

static void extend_craft(Parser *parser, Token keyword) {
    ProtoExtensionDecl decl;
    memset(&decl, 0, sizeof decl);
    decl.target_kind = PROTO_EXTENSION_TARGET_CRAFT;
    decl.line = keyword.line;

    bool header_ok = true;

    consume(parser, TOKEN_IDENTIFIER, "Expect target name after 'extend craft'");
    Token target_token = parser->previous;
    char target_name[PROTOHACK_MAX_IDENTIFIER + 1] = {0};
    if (!token_to_identifier(&target_token, target_name, sizeof target_name)) {
        error(parser, "Identifier is too long");
        header_ok = false;
        strncpy(target_name, "<invalid>", sizeof target_name - 1);
        target_name[sizeof target_name - 1] = '\0';
    }

    TemplateArgList target_args = {0};
    if (!try_parse_template_arguments(parser, &target_args)) {
        target_args.count = 0;
    }

    if (header_ok) {
        if (!populate_extension_spec(parser, &target_token, target_name, &target_args, &decl.target)) {
            header_ok = false;
        }
    } else {
        extension_spec_reset(&decl.target);
        strncpy(decl.target.name, target_name, sizeof decl.target.name - 1);
        decl.target.name[sizeof decl.target.name - 1] = '\0';
    }

    if (match(parser, TOKEN_WITH)) {
        while (!parser->had_error) {
            if (check(parser, TOKEN_LEFT_PAREN) || check(parser, TOKEN_EOF)) {
                error_at_current(parser, "Expect trait name after 'with'");
                break;
            }
            consume(parser, TOKEN_IDENTIFIER, "Expect trait name after 'with'");
            Token trait_token = parser->previous;
            char trait_name[PROTOHACK_MAX_IDENTIFIER + 1] = {0};
            bool trait_ok = token_to_identifier(&trait_token, trait_name, sizeof trait_name);
            if (!trait_ok) {
                error(parser, "Identifier is too long");
                strncpy(trait_name, "<invalid>", sizeof trait_name - 1);
                trait_name[sizeof trait_name - 1] = '\0';
            }

            TemplateArgList trait_args = {0};
            if (!try_parse_template_arguments(parser, &trait_args)) {
                trait_args.count = 0;
            }

            if (decl.trait_count >= PROTOHACK_MAX_EXTENSION_TRAITS) {
                error(parser, "Too many trait clauses in extension");
                trait_ok = false;
            }

            if (trait_ok) {
                ProtoExtensionTypeSpec trait_spec;
                extension_spec_reset(&trait_spec);
                if (!populate_extension_spec(parser, &trait_token, trait_name, &trait_args, &trait_spec)) {
                    trait_ok = false;
                }
                if (trait_ok && decl.trait_count < PROTOHACK_MAX_EXTENSION_TRAITS) {
                    decl.traits[decl.trait_count++] = trait_spec;
                }
            }

            if (!match(parser, TOKEN_COMMA)) {
                break;
            }
        }
    }

    if (header_ok) {
        header_ok = validate_extension_contract(parser, &target_token, &decl);
    }

    const ProtoFunction *template_function = NULL;
    if (header_ok) {
        template_function = resolve_extension_craft_template(parser, &decl);
        if (!template_function) {
            error(parser, "Craft extension target must be declared before 'extend'");
            header_ok = false;
        }
    }

    const ProtoTypeBindingSet *binding_set = &decl.target.bindings;
    char specialization_name[PROTOHACK_MAX_TEMPLATE_NAME] = {0};
    if (header_ok) {
        const char *label_ptrs[PROTOHACK_MAX_TYPE_PARAMS] = {0};
        for (uint8_t i = 0; i < decl.target.label_count && i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
            label_ptrs[i] = decl.target.labels[i][0] != '\0' ? decl.target.labels[i] : NULL;
        }
        if (!proto_function_format_specialization_name(decl.target.name,
                                                       template_function,
                                                       binding_set,
                                                       label_ptrs,
                                                       decl.target.label_count,
                                                       specialization_name,
                                                       sizeof specialization_name)) {
            error(parser, "Failed to format craft specialization name");
            header_ok = false;
        }
    }

    uint8_t template_arity = 0;
    ProtoTypeTag expected_param_types[PROTOHACK_MAX_PARAMS] = {0};
    ProtoTypeTag expected_return_type = PROTO_TYPE_NONE;
    if (header_ok) {
        template_arity = template_function->arity;
        for (uint8_t i = 0; i < template_arity && i < PROTOHACK_MAX_PARAMS; ++i) {
            expected_param_types[i] = resolve_extension_specialized_type(template_function,
                                                                         binding_set,
                                                                         template_function->param_types[i],
                                                                         template_function->param_type_params[i]);
        }
        expected_return_type = resolve_extension_specialized_type(template_function,
                                                                  binding_set,
                                                                  template_function->return_type,
                                                                  template_function->return_type_param);
    }

    ProtoTypeTag type_arguments[PROTOHACK_MAX_TYPE_PARAMS] = {PROTO_TYPE_ANY};
    uint8_t type_argument_count = binding_set ? binding_set->count : 0;
    if (type_argument_count > PROTOHACK_MAX_TYPE_PARAMS) {
        type_argument_count = PROTOHACK_MAX_TYPE_PARAMS;
    }
    for (uint8_t i = 0; i < type_argument_count; ++i) {
        ProtoTypeBinding binding = binding_set->entries[i];
        type_arguments[i] = (binding.tag != PROTO_TYPE_ANY && binding.param < 0) ? binding.tag : PROTO_TYPE_ANY;
    }

    ProtoFunction *function = NULL;
    if (header_ok) {
        function = proto_function_new(PROTO_FUNC_CRAFT, specialization_name);
        const char *type_param_names[PROTOHACK_MAX_TYPE_PARAMS] = {0};
        for (uint8_t i = 0; i < template_function->type_param_count && i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
            type_param_names[i] = template_function->type_params[i];
        }
        if (!proto_function_set_type_params(function, type_param_names, template_function->type_param_count)) {
            error(parser, "Failed to record type parameters for craft extension");
            header_ok = false;
        }
        if (header_ok) {
            if (!proto_function_set_type_arguments(function, type_arguments, type_argument_count)) {
                error(parser, "Failed to record specialization type arguments");
                header_ok = false;
            }
        }
        function->template_origin = template_function;
        function->bindings = *binding_set;
        function->return_type_param = template_function->return_type_param;
        memcpy(function->param_type_params, template_function->param_type_params, sizeof function->param_type_params);
    }

    CompilerContext context = {0};
    CompilerContext *previous = parser->compiler;
    const char *body_start = NULL;
    const char *body_end = NULL;

    if (header_ok && function) {
        context.function = function;
        context.chunk = &function->chunk;
        context.local_count = 0;
        context.scope_depth = 0;
        context.expected_return = expected_return_type;
        context.type_param_count = 0;
        context.enclosing = previous;
        compiler_context_reset_bindings(&context);

        Token synthetic = {.type = TOKEN_IDENTIFIER, .start = "", .length = 0, .line = keyword.line};
        context.locals[context.local_count++] = (Local){synthetic, 0, true, PROTO_TYPE_ANY, NULL};

        parser->compiler = &context;

        consume(parser, TOKEN_LEFT_PAREN, "Expect '(' after craft extension target");
        uint8_t param_index = 0;
        if (!check(parser, TOKEN_RIGHT_PAREN)) {
            do {
                if (param_index >= template_arity) {
                    error(parser, "Craft extension declares too many parameters");
                    header_ok = false;
                }

                consume(parser, TOKEN_IDENTIFIER, "Expect parameter name in craft extension");
                Token param_name = parser->previous;

                ProtoTypeTag declared_type = PROTO_TYPE_ANY;
                if (match(parser, TOKEN_AS)) {
                    declared_type = parse_type_annotation(parser, NULL);
                }

                ProtoTypeTag expected_type = PROTO_TYPE_ANY;
                if (param_index < template_arity) {
                    expected_type = expected_param_types[param_index];
                }

                if (declared_type != PROTO_TYPE_ANY && declared_type != expected_type) {
                    const char *expected_name = proto_type_tag_name(expected_type);
                    char message[160];
                    snprintf(message,
                             sizeof message,
                             "Craft extension parameter %u must have type %s",
                             (unsigned)(param_index + 1),
                             expected_name ? expected_name : "any");
                    error(parser, message);
                    header_ok = false;
                }

                if (function->arity < PROTOHACK_MAX_PARAMS && param_index < template_arity) {
                    function->param_types[param_index] = expected_type;
                    function->param_type_params[param_index] = template_function->param_type_params[param_index];
                }
                if (param_index < PROTOHACK_MAX_PARAMS) {
                    function->arity = (uint8_t)(param_index + 1);
                }

                add_local(parser, param_name, false, expected_type);
                CompilerContext *ctx = current_context(parser);
                if (ctx) {
                    ctx->locals[ctx->local_count - 1].depth = 0;
                }

                param_index++;
            } while (match(parser, TOKEN_COMMA));
        }
        consume(parser, TOKEN_RIGHT_PAREN, "Expect ')' after craft extension parameters");

        if (header_ok && param_index != template_arity) {
            error(parser, "Craft extension must declare the same number of parameters as the target craft");
            header_ok = false;
        }

        if (match(parser, TOKEN_GIVES)) {
            ProtoTypeTag declared_return = parse_type_annotation(parser, NULL);
            if (declared_return != PROTO_TYPE_ANY && declared_return != expected_return_type) {
                const char *expected_name = proto_type_tag_name(expected_return_type);
                char message[160];
                snprintf(message,
                         sizeof message,
                         "Craft extension must return %s",
                         expected_name ? expected_name : "any");
                error(parser, message);
                header_ok = false;
            }
        }

        function->return_type = expected_return_type;
        context.expected_return = expected_return_type;

        consume(parser, TOKEN_LEFT_BRACE, "Expect '{' to start craft extension body");
        body_start = parser->current.start;
        begin_scope(parser);
        while (!check(parser, TOKEN_RIGHT_BRACE) && !check(parser, TOKEN_EOF)) {
            declaration(parser);
        }
        body_end = parser->current.start;
        consume(parser, TOKEN_RIGHT_BRACE, "Expect '}' after craft extension body");
        end_scope(parser);

        emit_return(parser);
        sync_function_globals(parser, &function->chunk);

        parser->compiler = previous;
    } else {
        if (!parser->had_error) {
            // Attempt to consume body to recover from header failure.
            if (match(parser, TOKEN_LEFT_PAREN)) {
                int depth = 1;
                while (depth > 0 && !check(parser, TOKEN_EOF)) {
                    if (match(parser, TOKEN_LEFT_PAREN)) {
                        depth++;
                    } else if (match(parser, TOKEN_RIGHT_PAREN)) {
                        depth--;
                    } else {
                        parser_advance(parser);
                    }
                }
            }
            if (match(parser, TOKEN_LEFT_BRACE)) {
                int depth = 1;
                while (depth > 0 && !check(parser, TOKEN_EOF)) {
                    if (match(parser, TOKEN_LEFT_BRACE)) {
                        depth++;
                    } else if (match(parser, TOKEN_RIGHT_BRACE)) {
                        depth--;
                    } else {
                        parser_advance(parser);
                    }
                }
            }
        }
        parser->compiler = previous;
    }

    bool success = header_ok && !parser->had_error && function != NULL;
    if (!success) {
        if (function) {
            proto_function_free(function);
        }
        for (uint8_t i = 0; i < decl.trait_count; ++i) {
            (void)decl.traits[i];
        }
        return;
    }

    if (body_start && body_end && body_end >= body_start) {
        size_t length = (size_t)(body_end - body_start);
        decl.body_source = protohack_copy_string(body_start, length);
        decl.body_length = length;
    } else {
        decl.body_source = protohack_copy_string("", 0);
        decl.body_length = 0;
    }

    FunctionSpecializationEntry *existing = find_function_specialization(parser, specialization_name);
    uint16_t constant_index = 0;
    if (existing) {
        constant_index = existing->constant_index;
        if (constant_index < parser->chunk->constants_count) {
            ProtoValue *slot = &parser->chunk->constants[constant_index];
            proto_value_free(slot);
            *slot = proto_value_function(function);
        }
        if (existing->function && existing->function != template_function) {
            proto_function_free(existing->function);
        }
        existing->function = function;
    } else {
        Token saved_previous = parser->previous;
        parser->previous = target_token;
        constant_index = make_constant(parser, proto_value_function(function));
        parser->previous = saved_previous;
        if (!add_function_specialization(parser, specialization_name, constant_index, function)) {
            error(parser, "Too many craft specializations in module");
            return;
        }
    }

    ProtoChunk *chunk = current_chunk(parser);
    if (chunk) {
        if (chunk->extension_count >= chunk->extension_capacity) {
            size_t new_capacity = chunk->extension_capacity == 0 ? 4 : chunk->extension_capacity * 2;
            ProtoExtensionDecl *new_entries = (ProtoExtensionDecl *)realloc(chunk->extensions, new_capacity * sizeof *chunk->extensions);
            if (!new_entries) {
                PROTOHACK_FATAL("Failed to allocate extension metadata");
            }
            chunk->extensions = new_entries;
            chunk->extension_capacity = new_capacity;
        }
        chunk->extensions[chunk->extension_count++] = decl;
    }
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

    TypeParameterList type_params = {0};
    parse_type_parameter_list(parser, identifier, &type_params);

    int global_index = declare_global(parser, name, true);
    if (global_index < 0) {
        return;
    }

    parser->globals.defined[global_index] = true;

    ProtoFunction *function = proto_function_new(PROTO_FUNC_CRAFT, identifier);

    const char *type_param_names[PROTOHACK_MAX_TYPE_PARAMS] = {0};
    for (uint8_t i = 0; i < type_params.count && i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
        type_param_names[i] = type_params.names[i];
    }
    if (!proto_function_set_type_params(function, type_param_names, type_params.count)) {
        error(parser, "Failed to record type parameters for craft");
    }

    if (type_params.count > 0) {
        if (!register_function_template(parser, identifier, function, type_params.count)) {
            error(parser, "Unable to register generic craft");
        }
    }

    CompilerContext context = {0};
    context.function = function;
    context.chunk = &function->chunk;
    context.local_count = 0;
    context.scope_depth = 0;
    context.expected_return = PROTO_TYPE_NONE;
    context.type_param_count = type_params.count;
    for (uint8_t i = 0; i < type_params.count && i < PROTOHACK_MAX_TYPE_PARAMS; ++i) {
        context.type_params[i] = type_params.tokens[i];
    }
    context.enclosing = enclosing;
    compiler_context_reset_bindings(&context);

    Token synthetic = {.type = TOKEN_IDENTIFIER, .start = "", .length = 0, .line = name.line};
    context.locals[context.local_count++] = (Local){synthetic, 0, true, PROTO_TYPE_ANY, NULL};

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
            int8_t param_binding = -1;
            if (match(parser, TOKEN_AS)) {
                param_type = parse_type_annotation(parser, &param_binding);
            }
            if (function->arity < PROTOHACK_MAX_PARAMS) {
                function->param_types[function->arity] = param_type;
                function->param_type_params[function->arity] = param_binding;
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
    int8_t return_binding = -1;
    if (match(parser, TOKEN_GIVES)) {
        return_type = parse_type_annotation(parser, &return_binding);
    }
    function->return_type = return_type;
    function->return_type_param = return_binding;
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
    parser->globals.functions[global_index] = function;
    parser->globals.type_tags[global_index] = PROTO_TYPE_ANY;

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
        parser->globals.type_tags[index] = type_tag;
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
        if (is_local) {
            CompilerContext *ctx = current_context(parser);
            if (ctx && ctx->local_count > 0) {
                ctx->locals[ctx->local_count - 1].function_value = parser->recent_function_value;
            }
        } else if (index >= 0) {
            parser->globals.functions[index] = parser->recent_function_value;
        }
    } else {
        emit_byte(parser, PROTO_OP_NULL);
        if (!is_local && index >= 0) {
            parser->globals.functions[index] = NULL;
        }
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
    } else if (match(parser, TOKEN_CLASS)) {
        class_declaration(parser);
    } else if (match(parser, TOKEN_EXTEND)) {
        extend_declaration(parser);
    } else {
        statement(parser);
    }

    if (parser->panic_mode) {
        synchronize(parser);
    }
}

static void finalize_module_metadata(Parser *parser) {
    if (!parser || parser->had_error) {
        return;
    }

    ProtoChunk *chunk = parser->chunk;
    if (!chunk) {
        return;
    }

    free(chunk->binding_entries);
    chunk->binding_entries = NULL;
    chunk->binding_entry_count = 0;
    chunk->binding_entry_capacity = 0;

    size_t global_limit = chunk->globals_count;
    if (global_limit > PROTOHACK_MAX_GLOBALS) {
        global_limit = PROTOHACK_MAX_GLOBALS;
    }

    for (size_t i = 0; i < global_limit; ++i) {
        ProtoFunction *function = parser->globals.functions[i];
        if (!function) {
            continue;
        }
        if (function->bindings.count == 0) {
            continue;
        }
        if (chunk->binding_entry_count >= chunk->binding_entry_capacity) {
            size_t new_capacity = chunk->binding_entry_capacity == 0 ? 4 : chunk->binding_entry_capacity * 2;
            ProtoBindingMapEntry *new_entries = (ProtoBindingMapEntry *)realloc(chunk->binding_entries, new_capacity * sizeof *new_entries);
            if (!new_entries) {
                PROTOHACK_FATAL("Failed to allocate generic binding map");
            }
            chunk->binding_entries = new_entries;
            chunk->binding_entry_capacity = new_capacity;
        }
        ProtoBindingMapEntry *entry = &chunk->binding_entries[chunk->binding_entry_count++];
        entry->symbol_index = (uint32_t)i;
        entry->bindings = function->bindings;
    }

    if (chunk->binding_entry_count > 0) {
        chunk->module_flags |= PROTOHACK_MODULE_FLAG_HAS_BINDING_MAP;
    } else {
        chunk->module_flags &= ~PROTOHACK_MODULE_FLAG_HAS_BINDING_MAP;
    }
}

bool protohack_compile_source(const char *source, const char *origin_path, ProtoChunk *chunk, ProtoError *error) {
    if (!source || !chunk || !error) {
        if (error) {
            protoerror_set(error, 0, "Invalid arguments to compiler");
        }
        return false;
    }

    protoerror_reset(error);

    char *preprocessed = preprocess_includes(source, origin_path, error);
    if (!preprocessed) {
        return false;
    }

    Parser parser;
    parser_init(&parser, preprocessed, chunk, error);

    parser_advance(&parser);
    while (!check(&parser, TOKEN_EOF) && !parser.had_error) {
        declaration(&parser);
    }
    parser_advance(&parser);
    emit_return(&parser);

    finalize_module_metadata(&parser);

    bool success = !parser.had_error;
    free(preprocessed);
    return success;
}
