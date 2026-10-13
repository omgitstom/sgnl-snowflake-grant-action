import js from '@eslint/js';

export default [
  js.configs.recommended,
  {
    rules: {
      'no-console': 'off',
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    },
  },
];
