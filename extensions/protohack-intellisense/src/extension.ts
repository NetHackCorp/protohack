import * as vscode from 'vscode';

interface NativeFunction {
  readonly name: string;
  readonly signature: string;
  readonly detail: string;
  readonly documentation: string;
}

interface MethodInfo {
  readonly name: string;
  readonly signature: string;
  readonly location: vscode.Location;
  readonly declaringClass: string;
}

interface ClassInfo {
  readonly name: string;
  readonly location: vscode.Location;
  readonly methods: Map<string, MethodInfo>;
}

interface CraftInfo {
  readonly name: string;
  readonly parameters: string[];
  readonly returnType?: string;
  readonly signature: string;
  readonly location: vscode.Location;
}

interface DocumentIntelligence {
  readonly classes: Map<string, ClassInfo>;
  readonly crafts: Map<string, CraftInfo>;
  readonly variables: Map<string, vscode.Location>;
  readonly classMethods: Map<string, Map<string, MethodInfo>>;
  readonly variableTypes: Map<string, string>;
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

function analyzeDocument(document: vscode.TextDocument): DocumentIntelligence {
  const text = document.getText();

  const classes = new Map<string, ClassInfo>();
  const crafts = new Map<string, CraftInfo>();
  const variables = new Map<string, vscode.Location>();
  const classMethods = new Map<string, Map<string, MethodInfo>>();
  const variableTypes = new Map<string, string>();

  const classPattern = /\bclass\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*<[^>{}]+>)?\s*\{/g;
  let classMatch: RegExpExecArray | null;
  while ((classMatch = classPattern.exec(text)) !== null) {
    const className = classMatch[1];
    const classNameStart = classMatch.index + classMatch[0].indexOf(className);
    const classNameEnd = classNameStart + className.length;
    const classLocation = new vscode.Location(
      document.uri,
      new vscode.Range(document.positionAt(classNameStart), document.positionAt(classNameEnd))
    );

    const openBraceIndex = classMatch.index + classMatch[0].lastIndexOf('{');
    const block = extractBlock(text, openBraceIndex);
    const methods = new Map<string, MethodInfo>();

    if (block) {
      const methodPattern = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)/gm;
      let methodMatch: RegExpExecArray | null;
      while ((methodMatch = methodPattern.exec(block.body)) !== null) {
        const methodName = methodMatch[1];
        const methodParams = (methodMatch[2] ?? '').trim();
        const methodSignature = `${methodName}(${methodParams})`;
        const methodNameStart = block.bodyStart + methodMatch.index + methodMatch[0].indexOf(methodName);
        const methodNameEnd = methodNameStart + methodName.length;
        const methodLocation = new vscode.Location(
          document.uri,
          new vscode.Range(document.positionAt(methodNameStart), document.positionAt(methodNameEnd))
        );
        methods.set(methodName, {
          name: methodName,
          signature: methodSignature,
          location: methodLocation,
          declaringClass: className
        });
      }

      classPattern.lastIndex = block.end;
    }

    const classInfo: ClassInfo = { name: className, location: classLocation, methods };
    classes.set(className, classInfo);
    if (methods.size > 0) {
      classMethods.set(className, methods);
    }
  }

  const craftPattern = /\bcraft\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(?:gives\s+([A-Za-z0-9_\[\]]+))?\s*\{/g;
  let craftMatch: RegExpExecArray | null;
  while ((craftMatch = craftPattern.exec(text)) !== null) {
    const craftName = craftMatch[1];
    const paramsRaw = craftMatch[2] ?? '';
    const returnType = craftMatch[3];
    const nameStart = craftMatch.index + craftMatch[0].indexOf(craftName);
    const nameEnd = nameStart + craftName.length;
    const location = new vscode.Location(
      document.uri,
      new vscode.Range(document.positionAt(nameStart), document.positionAt(nameEnd))
    );
    const parameters = paramsRaw
      .split(',')
      .map(param => param.trim())
      .filter(param => param.length > 0);
    const signature = `${craftName}(${paramsRaw.trim()})${returnType ? ` gives ${returnType}` : ''}`;
    crafts.set(craftName, { name: craftName, parameters, returnType, signature, location });
    craftPattern.lastIndex = nameEnd;
  }

  const variablePattern = /\b(?:let|const)\s+([A-Za-z_][A-Za-z0-9_]*)/g;
  let variableMatch: RegExpExecArray | null;
  while ((variableMatch = variablePattern.exec(text)) !== null) {
    const variableName = variableMatch[1];
    const nameStart = variableMatch.index + variableMatch[0].indexOf(variableName);
    const nameEnd = nameStart + variableName.length;
    const location = new vscode.Location(
      document.uri,
      new vscode.Range(document.positionAt(nameStart), document.positionAt(nameEnd))
    );
    variables.set(variableName, location);
  }

  if (classes.size > 0) {
    const instancePattern = /\b(?:let|const)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(/g;
    let instanceMatch: RegExpExecArray | null;
    while ((instanceMatch = instancePattern.exec(text)) !== null) {
      const instanceName = instanceMatch[1];
      const constructorName = instanceMatch[2];
      if (classes.has(constructorName)) {
        variableTypes.set(instanceName, constructorName);
      }
    }
  }

  return {
    classes,
    crafts,
    variables,
    classMethods,
    variableTypes
  };
}

function extractBlock(text: string, openBraceIndex: number): { body: string; end: number; bodyStart: number } | undefined {
  let depth = 0;
  for (let i = openBraceIndex; i < text.length; i++) {
    const char = text[i];
    if (char === '{') {
      depth++;
    } else if (char === '}') {
      depth--;
      if (depth === 0) {
        const bodyStart = openBraceIndex + 1;
        const body = text.slice(bodyStart, i);
        return { body, end: i + 1, bodyStart };
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

class ProtohackWorkspaceIndex {
  private readonly documents = new Map<string, DocumentIntelligence>();

  async initialize(context: vscode.ExtensionContext): Promise<void> {
    vscode.workspace.textDocuments.forEach(document => this.indexDocument(document));

    context.subscriptions.push(
      vscode.workspace.onDidOpenTextDocument(document => this.indexDocument(document)),
      vscode.workspace.onDidCloseTextDocument(document => this.documents.delete(document.uri.toString())),
      vscode.workspace.onDidChangeTextDocument(event => this.indexDocument(event.document))
    );

    try {
      const files = await vscode.workspace.findFiles('**/*.{phk,phc}', '**/{node_modules,.git}/**');
      await Promise.all(
        files.map(async uri => {
          const key = uri.toString();
          if (this.documents.has(key)) {
            return;
          }
          try {
            const document = await vscode.workspace.openTextDocument(uri);
            this.indexDocument(document);
          } catch (error) {
            // ignore unreadable files
          }
        })
      );
    } catch (error) {
      // workspace may be untitled or restricted; ignore indexing failure
    }
  }

  getDocumentIntelligence(document: vscode.TextDocument): DocumentIntelligence {
    this.indexDocument(document);
    const key = document.uri.toString();
    return this.documents.get(key) ?? analyzeDocument(document);
  }

  getAggregateIntelligence(): DocumentIntelligence {
    const classes = new Map<string, ClassInfo>();
    const crafts = new Map<string, CraftInfo>();
    const variables = new Map<string, vscode.Location>();
    const classMethods = new Map<string, Map<string, MethodInfo>>();
    const variableTypes = new Map<string, string>();

    this.documents.forEach(intelligence => {
      intelligence.classes.forEach((classInfo, className) => {
        if (!classes.has(className)) {
          classes.set(className, classInfo);
        }
        if (classInfo.methods.size > 0) {
          const existing = classMethods.get(className) ?? new Map<string, MethodInfo>();
          classInfo.methods.forEach((methodInfo, methodName) => {
            if (!existing.has(methodName)) {
              existing.set(methodName, methodInfo);
            }
          });
          classMethods.set(className, existing);
        }
      });

      intelligence.crafts.forEach((craftInfo, craftName) => {
        if (!crafts.has(craftName)) {
          crafts.set(craftName, craftInfo);
        }
      });

      intelligence.variables.forEach((location, variableName) => {
        if (!variables.has(variableName)) {
          variables.set(variableName, location);
        }
      });

      intelligence.variableTypes.forEach((value, variableName) => {
        if (!variableTypes.has(variableName)) {
          variableTypes.set(variableName, value);
        }
      });
    });

    return { classes, crafts, variables, classMethods, variableTypes };
  }

  private indexDocument(document: vscode.TextDocument): void {
    if (document.languageId !== 'protohack') {
      return;
    }
    const intelligence = analyzeDocument(document);
    this.documents.set(document.uri.toString(), intelligence);
  }
}

class ProtohackCompletionProvider implements vscode.CompletionItemProvider {
  constructor(private readonly index: ProtohackWorkspaceIndex) {}

  provideCompletionItems(
    document: vscode.TextDocument,
    position: vscode.Position
  ): vscode.ProviderResult<vscode.CompletionItem[]> {
    const intelligence = this.index.getDocumentIntelligence(document);
    const workspaceIntelligence = this.index.getAggregateIntelligence();
    const linePrefix = document.lineAt(position.line).text.slice(0, position.character);
    const memberMatch = /([A-Za-z_][A-Za-z0-9_]*)\.\w*$/.exec(linePrefix);
    if (memberMatch) {
      const receiver = memberMatch[1];
      let targetClass: string | undefined;
      if (receiver === 'this') {
        targetClass = findEnclosingClass(document, position);
      } else {
        targetClass = intelligence.variableTypes.get(receiver);
        if (!targetClass && intelligence.classes.has(receiver)) {
          targetClass = receiver;
        }
        if (!targetClass && workspaceIntelligence.classes.has(receiver)) {
          targetClass = receiver;
        }
      }

      const methods = targetClass
        ? intelligence.classMethods.get(targetClass) ?? workspaceIntelligence.classMethods.get(targetClass)
        : undefined;
      if (methods && methods.size > 0) {
        const methodItems: vscode.CompletionItem[] = [];
        methods.forEach((methodInfo, methodName) => {
          const item = new vscode.CompletionItem(methodName, vscode.CompletionItemKind.Method);
          item.insertText = methodName;
          const relPath = vscode.workspace.asRelativePath(methodInfo.location.uri, true);
          item.detail = `${targetClass} method (${relPath})`;
          const markdown = new vscode.MarkdownString();
          markdown.appendCodeblock(methodInfo.signature, 'protohack');
          item.documentation = markdown;
          methodItems.push(item);
        });
        return methodItems;
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

    intelligence.classes.forEach((classInfo, className) => {
      const item = new vscode.CompletionItem(className, vscode.CompletionItemKind.Class);
      item.insertText = className;
      item.detail = 'Class declared in this file';
      if (classInfo.methods.size > 0) {
        const methodList = Array.from(classInfo.methods.values())
          .map(method => `- \`${method.signature}\``)
          .join('\n');
        item.documentation = new vscode.MarkdownString(`### Methods\n${methodList}`);
      }
      pushUnique(item);
    });

    intelligence.crafts.forEach((craftInfo, craftName) => {
      const item = new vscode.CompletionItem(craftName, vscode.CompletionItemKind.Function);
      item.insertText = new vscode.SnippetString(`${craftName}($0)`);
      item.detail = 'Craft declared in this file';
      const params = craftInfo.parameters.join(', ');
      const markdown = new vscode.MarkdownString();
      markdown.appendCodeblock(`craft ${craftName}(${params})${craftInfo.returnType ? ` gives ${craftInfo.returnType}` : ''}`, 'protohack');
      item.documentation = markdown;
      pushUnique(item);
    });

    intelligence.variables.forEach((location, variableName) => {
      const item = new vscode.CompletionItem(variableName, vscode.CompletionItemKind.Variable);
      item.insertText = variableName;
      item.detail = 'Variable declared in this file';
      const variableType = intelligence.variableTypes.get(variableName);
      if (variableType) {
        item.documentation = new vscode.MarkdownString(`Inferred type: **${variableType}**`);
      }
      pushUnique(item);
    });

    workspaceIntelligence.classes.forEach((classInfo, className) => {
      if (intelligence.classes.has(className)) {
        return;
      }
      const item = new vscode.CompletionItem(className, vscode.CompletionItemKind.Class);
      item.insertText = className;
      const relPath = vscode.workspace.asRelativePath(classInfo.location.uri, true);
      item.detail = `Class defined in ${relPath}`;
      if (classInfo.methods.size > 0) {
        const methodList = Array.from(classInfo.methods.values())
          .map(method => `- \`${method.signature}\``)
          .join('\n');
        const markdown = new vscode.MarkdownString();
        markdown.appendMarkdown(`**class ${className}** (_${relPath}_)\n\n`);
        markdown.appendMarkdown(`### Methods\n${methodList}`);
        item.documentation = markdown;
      }
      pushUnique(item);
    });

    workspaceIntelligence.crafts.forEach((craftInfo, craftName) => {
      if (intelligence.crafts.has(craftName)) {
        return;
      }
      const item = new vscode.CompletionItem(craftName, vscode.CompletionItemKind.Function);
      item.insertText = new vscode.SnippetString(`${craftName}($0)`);
      const relPath = vscode.workspace.asRelativePath(craftInfo.location.uri, true);
      item.detail = `Craft defined in ${relPath}`;
      const params = craftInfo.parameters.join(', ');
      const markdown = new vscode.MarkdownString();
      markdown.appendCodeblock(`craft ${craftName}(${params})${craftInfo.returnType ? ` gives ${craftInfo.returnType}` : ''}`, 'protohack');
      markdown.appendMarkdown(`\nDefined in _${relPath}_`);
      item.documentation = markdown;
      pushUnique(item);
    });

    return completions;
  }
}

class ProtohackHoverProvider implements vscode.HoverProvider {
  constructor(private readonly index: ProtohackWorkspaceIndex) {}

  provideHover(
    document: vscode.TextDocument,
    position: vscode.Position
  ): vscode.ProviderResult<vscode.Hover> {
    const range = document.getWordRangeAtPosition(position);
    if (!range) {
      return null;
    }
    const word = document.getText(range);
    const documentIntelligence = this.index.getDocumentIntelligence(document);
    const workspaceIntelligence = this.index.getAggregateIntelligence();

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

    const classInfo = workspaceIntelligence.classes.get(word);
    if (classInfo) {
      const relPath = vscode.workspace.asRelativePath(classInfo.location.uri, true);
      const markdown = new vscode.MarkdownString();
      markdown.appendMarkdown(`**class ${word}** (_${relPath}_)`);
      if (classInfo.methods.size > 0) {
        markdown.appendMarkdown('\n\n### Methods');
        classInfo.methods.forEach(method => {
          markdown.appendMarkdown(`\n- \`${method.signature}\``);
        });
      }
      return new vscode.Hover(markdown, range);
    }

    const craftInfo = workspaceIntelligence.crafts.get(word);
    if (craftInfo) {
      const relPath = vscode.workspace.asRelativePath(craftInfo.location.uri, true);
      const markdown = new vscode.MarkdownString();
      const params = craftInfo.parameters.join(', ');
      markdown.appendCodeblock(`craft ${craftInfo.name}(${params})${craftInfo.returnType ? ` gives ${craftInfo.returnType}` : ''}`, 'protohack');
      markdown.appendMarkdown(`\nDefined in _${relPath}_`);
      return new vscode.Hover(markdown, range);
    }

    const linePrefix = document.lineAt(position.line).text.slice(0, range.start.character);
    const methodReceiverMatch = /([A-Za-z_][A-Za-z0-9_]*)\s*\.$/.exec(linePrefix);
    if (methodReceiverMatch) {
      const receiver = methodReceiverMatch[1];
      let targetClass: string | undefined;
      if (receiver === 'this') {
        targetClass = findEnclosingClass(document, position);
      } else {
        targetClass = documentIntelligence.variableTypes.get(receiver);
        if (!targetClass && documentIntelligence.classes.has(receiver)) {
          targetClass = receiver;
        }
        if (!targetClass && workspaceIntelligence.classes.has(receiver)) {
          targetClass = receiver;
        }
      }

      if (targetClass) {
        const methodInfo = (documentIntelligence.classMethods.get(targetClass) ?? workspaceIntelligence.classMethods.get(targetClass))?.get(word);
        if (methodInfo) {
          const markdown = new vscode.MarkdownString();
          markdown.appendMarkdown(`**${methodInfo.declaringClass}.${methodInfo.name}**`);
          markdown.appendCodeblock(methodInfo.signature, 'protohack');
          const relPath = vscode.workspace.asRelativePath(methodInfo.location.uri, true);
          markdown.appendMarkdown(`\nDeclared in _${relPath}_`);
          return new vscode.Hover(markdown, range);
        }
      }
    }

    const variableLocation = documentIntelligence.variables.get(word);
    if (variableLocation) {
      const variableType = documentIntelligence.variableTypes.get(word);
      const markdown = new vscode.MarkdownString();
      markdown.appendMarkdown(`Variable **${word}**`);
      if (variableType) {
        markdown.appendMarkdown(`\nType: **${variableType}**`);
      }
      return new vscode.Hover(markdown, range);
    }

    return null;
  }
}

class ProtohackSignatureHelpProvider implements vscode.SignatureHelpProvider {
  constructor(private readonly index: ProtohackWorkspaceIndex) {}

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
    const workspaceIntelligence = this.index.getAggregateIntelligence();
    const native = NATIVE_FUNCTIONS.find(fn => fn.name === fnName);
    let signatureLabel: string | undefined;
    let documentation: string | vscode.MarkdownString | undefined;
    let parameters: string[] = [];

    if (native) {
      signatureLabel = native.signature;
      documentation = native.documentation;
      parameters = native.signature
        .replace(/^[^(]*\(/, '')
        .replace(/\).*/, '')
        .split(',')
        .map(param => param.trim())
        .filter(param => param.length > 0);
    } else {
      const craftInfo = workspaceIntelligence.crafts.get(fnName);
      if (!craftInfo) {
        return null;
      }
      parameters = [...craftInfo.parameters];
      signatureLabel = `${craftInfo.name}(${parameters.join(', ')})${craftInfo.returnType ? ` gives ${craftInfo.returnType}` : ''}`;
      const relPath = vscode.workspace.asRelativePath(craftInfo.location.uri, true);
      const md = new vscode.MarkdownString();
      md.appendMarkdown(`Defined in _${relPath}_`);
      documentation = md;
    }

    const signatureInfo = new vscode.SignatureInformation(signatureLabel, documentation);
    signatureInfo.parameters = parameters.map(param => new vscode.ParameterInformation(param));

    const signatureHelp = new vscode.SignatureHelp();
    signatureHelp.signatures = [signatureInfo];
    signatureHelp.activeSignature = 0;
    const commaCount = (line.match(/,/g) || []).length;
    signatureHelp.activeParameter = Math.min(commaCount, Math.max(signatureInfo.parameters.length - 1, 0));

    return signatureHelp;
  }
}

class ProtohackDefinitionProvider implements vscode.DefinitionProvider {
  constructor(private readonly index: ProtohackWorkspaceIndex) {}

  provideDefinition(
    document: vscode.TextDocument,
    position: vscode.Position
  ): vscode.ProviderResult<vscode.Definition> {
    const range = document.getWordRangeAtPosition(position, /[A-Za-z_][A-Za-z0-9_]*/);
    if (!range) {
      return null;
    }

    const word = document.getText(range);
    const documentIntelligence = this.index.getDocumentIntelligence(document);
    const workspaceIntelligence = this.index.getAggregateIntelligence();
    const locations: vscode.Location[] = [];

    const classInfo = workspaceIntelligence.classes.get(word);
    if (classInfo) {
      locations.push(classInfo.location);
    }

    const craftInfo = workspaceIntelligence.crafts.get(word);
    if (craftInfo) {
      locations.push(craftInfo.location);
    }

    const variableLocation = documentIntelligence.variables.get(word);
    if (variableLocation) {
      locations.push(variableLocation);
    }

    const linePrefix = document.lineAt(position.line).text.slice(0, range.start.character);
    const methodReceiverMatch = /([A-Za-z_][A-Za-z0-9_]*)\s*\.$/.exec(linePrefix);
    if (methodReceiverMatch) {
      const receiver = methodReceiverMatch[1];
      let targetClass: string | undefined;
      if (receiver === 'this') {
        targetClass = findEnclosingClass(document, position);
      } else {
        targetClass = documentIntelligence.variableTypes.get(receiver);
        if (!targetClass && documentIntelligence.classes.has(receiver)) {
          targetClass = receiver;
        }
        if (!targetClass && workspaceIntelligence.classes.has(receiver)) {
          targetClass = receiver;
        }
      }

      if (targetClass) {
        const methodInfo = (documentIntelligence.classMethods.get(targetClass) ?? workspaceIntelligence.classMethods.get(targetClass))?.get(word);
        if (methodInfo) {
          locations.push(methodInfo.location);
        }
      }
    }

    if (locations.length > 0) {
      return locations;
    }

    return null;
  }
}

export async function activate(context: vscode.ExtensionContext) {
  const languageSelector: vscode.DocumentSelector = [
    { language: 'protohack', scheme: 'file' },
    { language: 'protohack', scheme: 'untitled' }
  ];

  const index = new ProtohackWorkspaceIndex();
  try {
    await index.initialize(context);
  } catch (error) {
    console.error('Failed to initialize Protohack workspace index', error);
  }

  context.subscriptions.push(
    vscode.languages.registerCompletionItemProvider(languageSelector, new ProtohackCompletionProvider(index), '.', '"')
  );

  context.subscriptions.push(
    vscode.languages.registerHoverProvider(languageSelector, new ProtohackHoverProvider(index))
  );

  context.subscriptions.push(
    vscode.languages.registerSignatureHelpProvider(languageSelector, new ProtohackSignatureHelpProvider(index), '(', ',')
  );

  context.subscriptions.push(
    vscode.languages.registerDefinitionProvider(languageSelector, new ProtohackDefinitionProvider(index))
  );
}

export function deactivate() {
  // Nothing to clean up explicitly
}
