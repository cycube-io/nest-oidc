import { defineConfig, globalIgnores } from 'eslint/config';
import tseslint from 'typescript-eslint';
import globals from 'globals';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import js from '@eslint/js';
import { FlatCompat } from '@eslint/eslintrc';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const compat = new FlatCompat({
  baseDirectory: __dirname,
  recommendedConfig: js.configs.recommended,
  allConfig: js.configs.all,
});

export default defineConfig([
  globalIgnores(['**/.eslintrc.js']),
  {
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      compat.extends(
        'plugin:@typescript-eslint/recommended',
        'plugin:prettier/recommended',
      ),
    ],

    languageOptions: {
      globals: {
        ...globals.node,
        ...globals.jest,
      },
    },

    rules: {
      '@typescript-eslint/interface-name-prefix': 'off',
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/explicit-module-boundary-types': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': 'warn',
    },
  },
]);
