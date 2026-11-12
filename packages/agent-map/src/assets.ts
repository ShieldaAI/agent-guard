import { constants } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { fail } from './common.js';
import { readHostFile } from './boundary.js';

/** Viewer assets run in authenticated browsers: this user's or root's regular files, never a link. */
const ASSET_FILE = { noFollow: true, owner: 'service-or-root', singleLink: false, private: false } as const;

/** Load the fixed public assets once; never follow a replaced leaf or read beyond the cap. */
export async function loadMapAssets(directory: unknown): Promise<Map<string, { body: Buffer; mime: string }>> {
  const assets = new Map<string, { body: Buffer; mime: string }>();
  if (directory === undefined) return assets;
  if (
    typeof directory !== 'string' ||
    !isAbsolute(directory) ||
    typeof constants.O_NONBLOCK !== 'number' ||
    typeof constants.O_NOFOLLOW !== 'number'
  )
    fail('MAP_CONFIG_INVALID');
  const maximum = 4 * 1024 * 1024;
  for (const [name, mime] of [
    ['index.html', 'text/html; charset=utf-8'],
    ['app.js', 'text/javascript; charset=utf-8'],
    ['app.css', 'text/css; charset=utf-8'],
  ] as const) {
    try {
      assets.set(`/${name}`, { body: await readHostFile(join(directory, name), maximum, ASSET_FILE), mime });
    } catch {
      fail('MAP_CONFIG_INVALID');
    }
  }
  return assets;
}
