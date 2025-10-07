import * as assert from 'assert';
import * as vscode from 'vscode';

describe('Protohack IntelliSense', () => {
  it('registers completion items for keywords', async () => {
    const extension = vscode.extensions.getExtension('nethackcorp.protohack-intellisense');
    assert.ok(extension, 'Extension should be present');
    await extension.activate();

    const document = await vscode.workspace.openTextDocument({ language: 'protohack', content: 'le' });
    const editor = await vscode.window.showTextDocument(document);

    const position = new vscode.Position(0, 2);
    const completions = await vscode.commands.executeCommand<vscode.CompletionList>(
      'vscode.executeCompletionItemProvider',
      editor.document.uri,
      position
    );

    assert.ok(completions, 'Expected completion list');
    const hasLet = completions!.items.some(item => item.label === 'let');
    assert.ok(hasLet, 'Expected "let" keyword in completion list');
    const hasEncrypt = completions!.items.some(item => item.label === 'encrypt_file');
    assert.ok(hasEncrypt, 'Expected "encrypt_file" in completion list');
    const hasReadLine = completions!.items.some(item => item.label === 'read_line');
    assert.ok(hasReadLine, 'Expected "read_line" in completion list');
  });

  it('provides signature help for native functions', async () => {
    const extension = vscode.extensions.getExtension('nethackcorp.protohack-intellisense');
    assert.ok(extension, 'Extension should be present');
    await extension.activate();

    const document = await vscode.workspace.openTextDocument({ language: 'protohack', content: 'println(' });
    const editor = await vscode.window.showTextDocument(document);

    const position = new vscode.Position(0, 'println('.length);
    const signature = await vscode.commands.executeCommand<vscode.SignatureHelp | undefined>(
      'vscode.executeSignatureHelpProvider',
      editor.document.uri,
      position
    );

    assert.ok(signature, 'Expected signature help');
    assert.strictEqual(signature!.signatures[0].label, 'println(...values)');
  });

  it('suggests classes, crafts, and variables declared in the document', async () => {
    const extension = vscode.extensions.getExtension('nethackcorp.protohack-intellisense');
    assert.ok(extension, 'Extension should be present');
    await extension.activate();

    const content = `class Widget {
  init() {}
  area() {}
}

craft build(widget) gives num {
  return widget.area();
}

let w = Widget();
`;

    const document = await vscode.workspace.openTextDocument({ language: 'protohack', content });
    const editor = await vscode.window.showTextDocument(document);

    const completions = await vscode.commands.executeCommand<vscode.CompletionList>(
      'vscode.executeCompletionItemProvider',
      editor.document.uri,
      new vscode.Position(0, 0)
    );

    assert.ok(completions, 'Expected completion list');
    const labels = completions!.items.map(item => item.label);
    assert.ok(labels.includes('Widget'), 'Expected class name completion');
    assert.ok(labels.includes('build'), 'Expected craft name completion');
    assert.ok(labels.includes('w'), 'Expected variable name completion');
  });

  it('suggests class methods after member access', async () => {
    const extension = vscode.extensions.getExtension('nethackcorp.protohack-intellisense');
    assert.ok(extension, 'Extension should be present');
    await extension.activate();

    const content = `class Widget {
  init() {}
  area() {}
}

let w = Widget();

w.`;

    const document = await vscode.workspace.openTextDocument({ language: 'protohack', content });
    const editor = await vscode.window.showTextDocument(document);
    const position = new vscode.Position(content.split('\n').length - 1, 2);

    const completions = await vscode.commands.executeCommand<vscode.CompletionList>(
      'vscode.executeCompletionItemProvider',
      editor.document.uri,
      position
    );

    assert.ok(completions, 'Expected completion list');
    const labels = completions!.items.map(item => item.label);
    assert.ok(labels.includes('area'), 'Expected method completion for receiver instance');
  });
});
