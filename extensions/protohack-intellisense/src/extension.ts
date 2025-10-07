import * as vscode from 'vscode';

interface NativeFunction {
  readonly name: string;
  readonly signature: string;
  readonly detail: string;
  readonly documentation: string;
}

const KEYWORDS: string[] = [
  'let',
  'const',
  'craft',
  'class',
  'yield',
  'if',
  'else',
  'while',
  'for',
  'break',
  'continue',
  'return',
  'and',
  'or',
  'true',
  'false',
  'null',
  'this',
  'carve',
  'etch',
  'probe',
  'inc'
];

const NATIVE_FUNCTIONS: NativeFunction[] = [
  {
    name: 'clock',
    signature: 'clock()',
    detail: 'clock(): num',
    documentation: 'Returns the number of seconds since the VM started as a floating-point value.'
  },
  {
    name: 'sleep',
    signature: 'sleep(ms)',
    detail: 'sleep(ms: num): null',
    documentation: 'Blocks execution for the specified number of milliseconds.'
  },
  {
    name: 'rand',
    signature: 'rand(max?)',
    detail: 'rand(max?: num): num',
    documentation: 'Returns a pseudo-random number. Without arguments it returns a float in [0,1). With a max argument it returns an integer in [0,max).'
  },
  {
    name: 'rand_bytes',
    signature: 'rand_bytes(count)',
    detail: 'rand_bytes(count: num): raw',
    documentation: 'Generates a deterministic pseudo-random byte buffer with the requested length.'
  },
  {
    name: 'sqrt',
    signature: 'sqrt(value)',
    detail: 'sqrt(value: num): num',
    documentation: 'Computes the square root of the provided number.'
  },
  {
    name: 'pow',
    signature: 'pow(base, exp)',
    detail: 'pow(base: num, exp: num): num',
    documentation: 'Raises a base to the given exponent.'
  },
  {
    name: 'len',
    signature: 'len(value)',
    detail: 'len(value: any): num',
    documentation: 'Returns the length of strings, typed memory blocks, or formatted values.'
  },
  {
    name: 'to_string',
    signature: 'to_string(value)',
    detail: 'to_string(value: any): text',
    documentation: 'Converts the provided Protohack value into its string representation.'
  },
  {
    name: 'upper',
    signature: 'upper(text)',
    detail: 'upper(text: text): text',
    documentation: 'Transforms the input text to uppercase.'
  },
  {
    name: 'lower',
    signature: 'lower(text)',
    detail: 'lower(text: text): text',
    documentation: 'Transforms the input text to lowercase.'
  },
  {
    name: 'hex_encode',
    signature: 'hex_encode(value)',
    detail: 'hex_encode(value: raw | text | any): text',
    documentation: 'Encodes raw bytes or text to lowercase hexadecimal representation.'
  },
  {
    name: 'hex_decode',
    signature: 'hex_decode(text)',
    detail: 'hex_decode(text: text): raw',
    documentation: 'Decodes a hexadecimal string into a raw byte buffer.'
  },
  {
    name: 'read_line',
    signature: 'read_line(prompt?)',
    detail: 'read_line(prompt?: text): text | null',
    documentation: 'Reads a line from stdin, optionally displaying a prompt, and returns the captured text (or null on EOF).'
  },
  {
    name: 'encrypt_file',
    signature: 'encrypt_file(inputPath, outputPath, key?)',
    detail: 'encrypt_file(inputPath: text, outputPath: text, key?: text): text',
    documentation: 'Encrypts the entire input file using a generated or supplied hexadecimal key. Returns the key used for encryption.'
  },
  {
    name: 'decrypt_file',
    signature: 'decrypt_file(inputPath, outputPath, key)',
    detail: 'decrypt_file(inputPath: text, outputPath: text, key: text): null',
    documentation: 'Decrypts a file that was previously encrypted with encrypt_file using the provided hexadecimal key.'
  },
  {
    name: 'complex_add',
    signature: 'complex_add(aReal, aImag, bReal, bImag)',
    detail: 'complex_add(aReal: num, aImag: num, bReal: num, bImag: num): numeric[2]',
    documentation: 'Adds two complex numbers and returns typed numeric memory `[real, imag]`.'
  },
  {
    name: 'complex_sub',
    signature: 'complex_sub(aReal, aImag, bReal, bImag)',
    detail: 'complex_sub(aReal: num, aImag: num, bReal: num, bImag: num): numeric[2]',
    documentation: 'Subtracts one complex number from another and returns typed numeric memory `[real, imag]`.'
  },
  {
    name: 'complex_mul',
    signature: 'complex_mul(aReal, aImag, bReal, bImag)',
    detail: 'complex_mul(aReal: num, aImag: num, bReal: num, bImag: num): numeric[2]',
    documentation: 'Multiplies two complex numbers and returns typed numeric memory `[real, imag]`.'
  },
  {
    name: 'complex_div',
    signature: 'complex_div(aReal, aImag, bReal, bImag)',
    detail: 'complex_div(aReal: num, aImag: num, bReal: num, bImag: num): numeric[2]',
    documentation: 'Divides the first complex number by the second and returns typed numeric memory `[real, imag]`. Emits an error when dividing by zero.'
  },
  {
    name: 'complex_abs',
    signature: 'complex_abs(real, imag)',
    detail: 'complex_abs(real: num, imag: num): num',
    documentation: 'Returns the magnitude of a complex number represented by real and imaginary components.'
  },
  {
    name: 'complex_exp',
    signature: 'complex_exp(real, imag)',
    detail: 'complex_exp(real: num, imag: num): numeric[2]',
    documentation: 'Computes the complex exponential of `real + imag * i` and returns typed numeric memory `[real, imag]`.'
  },
  {
    name: 'println',
    signature: 'println(...values)',
    detail: 'println(values: any[]): null',
    documentation: 'Prints each argument separated by spaces followed by a newline.'
  }
];

const MEMORY_TYPES: string[] = ['numeric', 'flag', 'text', 'raw', 'any'];

interface DocumentIntelligence {
  readonly classNames: Set<string>;
  readonly craftNames: Set<string>;
  readonly variableNames: Set<string>;
  readonly classMethods: Map<string, Set<string>>;
  readonly variableTypes: Map<string, string>;
}

function analyzeDocument(document: vscode.TextDocument): DocumentIntelligence {
  const text = document.getText();

  const classNames = new Set<string>();
  const craftNames = new Set<string>();
  const variableNames = new Set<string>();
  const classMethods = new Map<string, Set<string>>();
  const variableTypes = new Map<string, string>();

  const classPattern = /class\s+([A-Za-z_][A-Za-z0-9_]*)[^\S\n]*\{/g;
  let classMatch: RegExpExecArray | null;
  while ((classMatch = classPattern.exec(text)) !== null) {
    const className = classMatch[1];
    classNames.add(className);

    const openBraceIndex = text.indexOf('{', classMatch.index);
    if (openBraceIndex === -1) {
      continue;
    }
    const block = extractBlock(text, openBraceIndex);
    if (!block) {
      continue;
    }
    const methods = new Set<string>();
    const methodPattern = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(/gm;
    let methodMatch: RegExpExecArray | null;
    while ((methodMatch = methodPattern.exec(block.body)) !== null) {
      methods.add(methodMatch[1]);
    }
    if (methods.size > 0) {
      classMethods.set(className, methods);
    }
    classPattern.lastIndex = block.end;
  }

  const craftPattern = /\bcraft\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/g;
  let craftMatch: RegExpExecArray | null;
  while ((craftMatch = craftPattern.exec(text)) !== null) {
    craftNames.add(craftMatch[1]);
  }

  const variablePattern = /\b(?:let|const)\s+([A-Za-z_][A-Za-z0-9_]*)/g;
  let variableMatch: RegExpExecArray | null;
  while ((variableMatch = variablePattern.exec(text)) !== null) {
    variableNames.add(variableMatch[1]);
  }

  if (classNames.size > 0) {
    const instancePattern = /\b(?:let|const)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(/g;
    let instanceMatch: RegExpExecArray | null;
    while ((instanceMatch = instancePattern.exec(text)) !== null) {
      const instanceName = instanceMatch[1];
      const constructorName = instanceMatch[2];
      if (classNames.has(constructorName)) {
        variableTypes.set(instanceName, constructorName);
      }
    }
  }

  return {
    classNames,
    craftNames,
    variableNames,
    classMethods,
    variableTypes
  };
}

function extractBlock(text: string, openBraceIndex: number): { body: string; end: number } | undefined {
  let depth = 0;
  for (let i = openBraceIndex; i < text.length; i++) {
    const char = text[i];
    if (char === '{') {
      depth++;
    } else if (char === '}') {
      depth--;
      if (depth === 0) {
        const body = text.slice(openBraceIndex + 1, i);
        return { body, end: i + 1 };
      }
    }
  }
  return undefined;
}

function findEnclosingClass(document: vscode.TextDocument, position: vscode.Position): string | undefined {
  for (let line = position.line; line >= 0; line--) {
    const text = document.lineAt(line).text;
    const match = /class\s+([A-Za-z_][A-Za-z0-9_]*)/.exec(text);
    if (match) {
      return match[1];
    }
  }
  return undefined;
}

class ProtohackCompletionProvider implements vscode.CompletionItemProvider {
  provideCompletionItems(
    document: vscode.TextDocument,
    position: vscode.Position
  ): vscode.ProviderResult<vscode.CompletionItem[]> {
    const intelligence = analyzeDocument(document);
    const linePrefix = document.lineAt(position.line).text.slice(0, position.character);
    const memberMatch = /([A-Za-z_][A-Za-z0-9_]*)\.\w*$/.exec(linePrefix);
    if (memberMatch) {
      const receiver = memberMatch[1];
      let targetClass: string | undefined;
      if (receiver === 'this') {
        targetClass = findEnclosingClass(document, position);
      } else {
        targetClass = intelligence.variableTypes.get(receiver);
        if (!targetClass && intelligence.classNames.has(receiver)) {
          targetClass = receiver;
        }
      }

      const methodNames = targetClass ? intelligence.classMethods.get(targetClass) : undefined;
      if (methodNames && methodNames.size > 0) {
        return Array.from(methodNames).map(method => {
          const item = new vscode.CompletionItem(method, vscode.CompletionItemKind.Method);
          item.insertText = method;
          item.detail = `${targetClass} method`;
          return item;
        });
      }
      return [];
    }

    const completions: vscode.CompletionItem[] = [];
    const addedLabels = new Set<string>();
    const pushUnique = (item: vscode.CompletionItem) => {
      const label = typeof item.label === 'string' ? item.label : item.label?.label ?? '';
      if (label && addedLabels.has(label)) {
        return;
      }
      if (label) {
        addedLabels.add(label);
      }
      completions.push(item);
    };

    KEYWORDS.forEach(keyword => {
      const item = new vscode.CompletionItem(keyword, vscode.CompletionItemKind.Keyword);
      item.insertText = keyword;
      item.detail = 'Protohack keyword';
      pushUnique(item);
    });

    MEMORY_TYPES.forEach(type => {
      const item = new vscode.CompletionItem(type, vscode.CompletionItemKind.Class);
      item.insertText = type;
      item.detail = 'Protohack typed memory identifier';
      pushUnique(item);
    });

    NATIVE_FUNCTIONS.forEach(fn => {
      const item = new vscode.CompletionItem(fn.name, vscode.CompletionItemKind.Function);
      item.insertText = new vscode.SnippetString(`${fn.name}($0)`);
      item.detail = fn.detail;
      item.documentation = new vscode.MarkdownString(fn.documentation);
      pushUnique(item);
    });

    const snippet = new vscode.CompletionItem('craft snippet', vscode.CompletionItemKind.Snippet);
    snippet.label = 'craft';
    snippet.detail = 'craft snippet';
    snippet.insertText = new vscode.SnippetString(
      'craft ${1:name}(${2:args}) gives ${3:type} {\n\t$0\n}'
    );
    snippet.documentation = new vscode.MarkdownString('Create a new craft (function) block.');
    pushUnique(snippet);

    const includeSnippet = new vscode.CompletionItem('inc', vscode.CompletionItemKind.Snippet);
    includeSnippet.insertText = new vscode.SnippetString('inc("${1:path}");');
    includeSnippet.detail = 'Include directive';
    includeSnippet.documentation = new vscode.MarkdownString('Includes another Protohack source file before compilation.');
    pushUnique(includeSnippet);

    const classSnippet = new vscode.CompletionItem('class skeleton', vscode.CompletionItemKind.Snippet);
    classSnippet.label = 'class';
    classSnippet.detail = 'class skeleton';
    classSnippet.insertText = new vscode.SnippetString(`class \${1:Name} {
  init(\${2:params}) {
    $0
  }
}
`);
    classSnippet.documentation = new vscode.MarkdownString('Create a class with an initializer skeleton.');
    pushUnique(classSnippet);

    intelligence.classNames.forEach(className => {
      const item = new vscode.CompletionItem(className, vscode.CompletionItemKind.Class);
      item.insertText = className;
      item.detail = 'Class declared in this file';
      pushUnique(item);
    });

    intelligence.craftNames.forEach(craftName => {
      const item = new vscode.CompletionItem(craftName, vscode.CompletionItemKind.Function);
      item.insertText = new vscode.SnippetString(`${craftName}($0)`);
      item.detail = 'Craft declared in this file';
      pushUnique(item);
    });

    intelligence.variableNames.forEach(variableName => {
      const item = new vscode.CompletionItem(variableName, vscode.CompletionItemKind.Variable);
      item.insertText = variableName;
      item.detail = 'Variable declared in this file';
      pushUnique(item);
    });

    return completions;
  }
}

class ProtohackHoverProvider implements vscode.HoverProvider {
  provideHover(
    document: vscode.TextDocument,
    position: vscode.Position
  ): vscode.ProviderResult<vscode.Hover> {
    const range = document.getWordRangeAtPosition(position);
    if (!range) {
      return null;
    }
    const word = document.getText(range);

    const native = NATIVE_FUNCTIONS.find(fn => fn.name === word);
    if (native) {
      const markdown = new vscode.MarkdownString();
      markdown.appendCodeblock(native.signature, 'protohack');
      markdown.appendMarkdown(`\n${native.documentation}`);
      return new vscode.Hover(markdown, range);
    }

    if (KEYWORDS.includes(word)) {
      const markdown = new vscode.MarkdownString(`**${word}** is a Protohack keyword.`);
      return new vscode.Hover(markdown, range);
    }

    if (MEMORY_TYPES.includes(word)) {
      const markdown = new vscode.MarkdownString();
      markdown.appendMarkdown(`**${word}** is a typed memory space identifier.`);
      switch (word) {
        case 'numeric':
          markdown.appendMarkdown('\nUse with `carve numeric(size)` to allocate floating-point buffers.');
          break;
        case 'flag':
          markdown.appendMarkdown('\nStores boolean values packed in bytes.');
          break;
        case 'text':
          markdown.appendMarkdown('\nStores UTF-8 characters, useful for manual string manipulation.');
          break;
        case 'raw':
          markdown.appendMarkdown('\nStores uninterpreted bytes.');
          break;
        case 'any':
          markdown.appendMarkdown('\nGeneric memory block compatible with any typed access.');
          break;
      }
      return new vscode.Hover(markdown, range);
    }

    return null;
  }
}

class ProtohackSignatureHelpProvider implements vscode.SignatureHelpProvider {
  provideSignatureHelp(
    document: vscode.TextDocument,
    position: vscode.Position
  ): vscode.ProviderResult<vscode.SignatureHelp> {
    const line = document.lineAt(position.line).text.slice(0, position.character);
    const match = /(\w+)\s*\([^(]*$/.exec(line);
    if (!match) {
      return null;
    }
    const fnName = match[1];
    const native = NATIVE_FUNCTIONS.find(fn => fn.name === fnName);
    if (!native) {
      return null;
    }

    const signatureInfo = new vscode.SignatureInformation(native.signature, native.documentation);
    const params = native.signature
      .replace(/^[^(]*\(/, '')
      .replace(/\).*/, '')
      .split(',')
      .map(param => param.trim())
      .filter(param => param.length > 0);

    signatureInfo.parameters = params.map(param => new vscode.ParameterInformation(param));

    const signatureHelp = new vscode.SignatureHelp();
    signatureHelp.signatures = [signatureInfo];
    signatureHelp.activeSignature = 0;
    const commaCount = (line.match(/,/g) || []).length;
    signatureHelp.activeParameter = Math.min(commaCount, signatureInfo.parameters.length - 1);

    return signatureHelp;
  }
}

export function activate(context: vscode.ExtensionContext) {
  const languageSelector: vscode.DocumentSelector = [
    { language: 'protohack', scheme: 'file' },
    { language: 'protohack', scheme: 'untitled' }
  ];

  context.subscriptions.push(
    vscode.languages.registerCompletionItemProvider(languageSelector, new ProtohackCompletionProvider(), '.', '"')
  );

  context.subscriptions.push(
    vscode.languages.registerHoverProvider(languageSelector, new ProtohackHoverProvider())
  );

  context.subscriptions.push(
    vscode.languages.registerSignatureHelpProvider(languageSelector, new ProtohackSignatureHelpProvider(), '(', ',')
  );
}

export function deactivate() {
  // Nothing to clean up explicitly
}
