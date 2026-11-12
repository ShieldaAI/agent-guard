import { build } from 'esbuild';
import { realpathSync } from 'node:fs';
import { mkdir, rm, copyFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = fileURLToPath(new URL('.', import.meta.url));
// The demo runs the real MapService in the page. Its JSON helpers import three Node built-ins;
// each resolves to a small stand-in under src/shims. Any other `node:` import fails the build,
// so a Node-only dependency cannot reach the browser unnoticed.
const SHIMS = Object.freeze({
  'node:buffer': 'buffer.mjs',
  'node:crypto': 'crypto.mjs',
  'node:util/types': 'util-types.mjs',
});
export const nodeShims = {
  name: 'node-shims',
  setup(context) {
    context.onResolve({ filter: /^node:/ }, args =>
      Object.hasOwn(SHIMS, args.path)
        ? { path: fileURLToPath(new URL(`./src/shims/${SHIMS[args.path]}`, import.meta.url)) }
        : { errors: [{ text: `No browser stand-in for ${args.path} (imported by ${args.importer})` }] },
    );
  },
};
/** The one set of bundle options, shared with the bundle test so the two cannot drift. */
export const viewerBuildOptions = Object.freeze({
  absWorkingDir: root,
  entryPoints: ['src/app.jsx'],
  bundle: true,
  minify: true,
  sourcemap: false,
  platform: 'browser',
  target: ['es2022'],
  outfile: 'dist/app.js',
  define: { 'process.env.NODE_ENV': '"production"' },
  legalComments: 'inline',
  plugins: [nodeShims],
});
export async function buildViewer() {
  await rm(new URL('./dist/', import.meta.url), { recursive: true, force: true });
  await mkdir(new URL('./dist/', import.meta.url), { recursive: true });
  await build(viewerBuildOptions);
  await copyFile(new URL('./src/index.html', import.meta.url), new URL('./dist/index.html', import.meta.url));
}
// Build only when run as a script; importing this module (the bundle test does) builds nothing.
const entry = process.argv[1];
if (entry && pathToFileURL(realpathSync(entry)).href === import.meta.url) await buildViewer();
