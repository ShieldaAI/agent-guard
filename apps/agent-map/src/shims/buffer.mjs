// Browser stand-in for `node:buffer`, used only when the demo bundles the real MapService.
// The service and its JSON copier need one thing from it: the UTF-8 length of a string.
const encoder = new TextEncoder();
export const Buffer = Object.freeze({
  byteLength: text => encoder.encode(String(text)).length,
});
