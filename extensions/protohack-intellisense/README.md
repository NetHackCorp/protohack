# Protohack IntelliSense

Protohack IntelliSense enrichit Visual Studio Code avec des complétions, info-bulles et aides à la signature pour le langage Protohack. L'extension reconnaît aussi les fichiers `.phk` et fournit une coloration syntaxique de base.

## Fonctionnalités

- Suggestions de mots-clés, types mémoire et snippets courants (`craft`, `inc`).
- Liste des fonctions natives avec documentation intégrée.
- Info-bulles décrivant les fonctions natives et les mots-clés.
- Aide à la signature pour rappeler les paramètres des fonctions natives.
- Coloration syntaxique simple (keywords, commentaires, chaînes, nombres, fonctions natives).

## Installation locale

```powershell
cd extensions/protohack-intellisense
npm install
npm run compile
```

Ensuite, appuyez sur `F5` dans VS Code pour lancer une nouvelle fenêtre en mode Extension Development Host.

## Tests

```powershell
npm test
```

Le script exécute la compilation TypeScript puis lance les tests d'intégration via `@vscode/test-electron`.

## Publier le package

```powershell
npm run package
```

La commande produit un fichier `.vsix` prêt à être partagé ou installé via la commande `code --install-extension`.

## Dossier projet

```
extensions/protohack-intellisense
├── package.json
├── tsconfig.json
├── language-configuration.json
├── syntaxes/
├── src/
└── README.md
```
