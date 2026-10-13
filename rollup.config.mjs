import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import terser from '@rollup/plugin-terser';

const NODE_BUILTINS = ['fs', 'path', 'url', 'util', 'crypto', 'https', 'http', 'os', 'stream', 'events', 'buffer'];

export default {
  input: 'src/script.mjs',
  output: {
    file: 'dist/index.js',
    format: 'cjs',
    banner: '// MIT License - Copyright (c) SGNL Engineering',
  },
  external: NODE_BUILTINS,
  plugins: [
    resolve({ preferBuiltins: true }),
    commonjs(),
    terser(),
  ],
};
