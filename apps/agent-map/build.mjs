import { build } from 'esbuild';
import { mkdir, rm, copyFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('.', import.meta.url));
await rm(new URL('./dist/', import.meta.url), { recursive: true, force: true });
await mkdir(new URL('./dist/', import.meta.url), { recursive: true });
await build({ absWorkingDir: root, entryPoints: ['src/app.jsx'], bundle: true,
  minify: true, sourcemap: false, target: ['es2022'], outfile: 'dist/app.js',
  define: { 'process.env.NODE_ENV': '"production"' }, legalComments: 'inline' });
await copyFile(new URL('./src/index.html', import.meta.url), new URL('./dist/index.html', import.meta.url));
