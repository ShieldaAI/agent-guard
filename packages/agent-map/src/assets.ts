import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { fail } from './boundary.js';

/** Load the fixed public assets once; never follow a replaced leaf or read beyond the cap. */
export async function loadMapAssets(directory: unknown): Promise<Map<string, { body: Buffer; mime: string }>> {
  const assets = new Map<string, { body: Buffer; mime: string }>();
  if (directory === undefined) return assets;
  if (typeof directory !== 'string' || !isAbsolute(directory) ||
      typeof constants.O_NONBLOCK !== 'number' || typeof constants.O_NOFOLLOW !== 'number') fail('MAP_CONFIG_INVALID');
  const maximum = 4 * 1024 * 1024;
  for (const [name, mime] of [['index.html', 'text/html; charset=utf-8'], ['app.js', 'text/javascript; charset=utf-8'], ['app.css', 'text/css; charset=utf-8']] as const) {
    try {
      const file = await open(join(directory, name), constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
      try {
        const info = await file.stat();
        if (!info.isFile() || info.size > maximum) fail('MAP_CONFIG_INVALID');
        const data = Buffer.alloc(maximum + 1); let bytes = 0;
        while (bytes < data.length) {
          const read = await file.read(data, bytes, data.length - bytes, null);
          if (!read.bytesRead) break;
          bytes += read.bytesRead;
        }
        if (bytes > maximum) fail('MAP_CONFIG_INVALID');
        // Do not retain the full maximum-sized allocation for a small asset.
        assets.set(`/${name}`, { body: Buffer.from(data.subarray(0, bytes)), mime });
      } finally { await file.close(); }
    } catch { fail('MAP_CONFIG_INVALID'); }
  }
  return assets;
}
