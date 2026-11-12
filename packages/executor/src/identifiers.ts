/**
 * The one identifier rule for inventory data: tenant, task, tool, source and manifest
 * identifiers in the ledger projection, the observer server, host manifests and MCP
 * inventory all pass through it, so a value one stage accepts is never refused by the next.
 */
export const MAX_IDENTIFIER_CODE_POINTS = 4096;

/**
 * True for a string of 1 to 4,096 Unicode code points that is not only whitespace or
 * separator controls, has no NUL and no unpaired surrogate (the Python consumer requires
 * UTF-8 scalar values).
 */
export function isInventoryIdentifier(value: unknown): value is string {
  if (
    typeof value !== 'string' ||
    // More UTF-16 units than twice the limit cannot fit: refuse before any scan.
    value.length > MAX_IDENTIFIER_CODE_POINTS * 2 ||
    /^[\s\u001c-\u001f\u0085]*$/u.test(value) ||
    value.includes('\0') ||
    /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)
  )
    return false;
  // UTF-16 length bounds the code-point count from above; short identifiers need no array.
  return value.length <= MAX_IDENTIFIER_CODE_POINTS || [...value].length <= MAX_IDENTIFIER_CODE_POINTS;
}
