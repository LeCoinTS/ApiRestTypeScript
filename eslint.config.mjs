import typescriptEslintParser from "@typescript-eslint/parser"
import typescriptEslintPlugin from "@typescript-eslint/eslint-plugin"

export default [
  {
    files: ["**/*.ts"],
    ignores: ["eslint.config.mjs"], // Exclut explicitement ce fichier
    languageOptions: {
      parser: typescriptEslintParser,
      sourceType: "module",
      parserOptions: {
        project: "./tsconfig.json",
        tsconfigRootDir: process.cwd(),
      },
    },
    plugins: {
      "@typescript-eslint": typescriptEslintPlugin,
    },
    rules: {
      // Pour alerter en cas de variable créée / non utilisée
      "@typescript-eslint/no-unused-vars": "warn",

      // Pour alerter sur les accès non sécurisés à des propriétés de type `any`
      "@typescript-eslint/no-unsafe-member-access": "warn", // Ou 'error' pour être plus strict

      // Pour alerter sur l'utilisation du mot clef 'any' (pour forcer un typage explicite)
      "@typescript-eslint/no-explicit-any": "warn",

      // Pour alerter sur le manque de typage explicite du retour de fonctions
      "@typescript-eslint/explicit-function-return-type": [
        "warn",
        {
          allowExpressions: false,
          allowTypedFunctionExpressions: true,
          allowHigherOrderFunctions: true,
        },
      ],

      // Pour alerter sur le manque de typage explicite variables
      "@typescript-eslint/typedef": [
        "warn",
        {
          variableDeclaration: true, // Exige un type pour toutes les déclarations de variables
          variableDeclarationIgnoreFunction: true, // Ignore les variables dans les déclarations de fonctions (facultatif)
          parameter: true, // Exige un type pour les paramètres
        },
      ],
    },
  },
]
