'use strict';
// Minimal ZIP reader (stored + deflate) — enough to unpack Xray release archives
// without pulling in a dependency. ZIP64 is not supported (archives < 4 GB).

const zlib = require('zlib');

const SIG_EOCD = 0x06054b50;
const SIG_CDIR = 0x02014b50;
const SIG_LOCAL = 0x04034b50;

function findEocd(buf) {
  const min = Math.max(0, buf.length - 22 - 0xffff);
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf.readUInt32LE(i) === SIG_EOCD) return i;
  }
  throw new Error('zip: end of central directory not found');
}

function listEntries(buf) {
  const eocd = findEocd(buf);
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  const entries = [];
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(off) !== SIG_CDIR) throw new Error('zip: bad central directory entry');
    const method = buf.readUInt16LE(off + 10);
    const compressedSize = buf.readUInt32LE(off + 20);
    const size = buf.readUInt32LE(off + 24);
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const commentLen = buf.readUInt16LE(off + 32);
    const localOffset = buf.readUInt32LE(off + 42);
    const name = buf.toString('utf8', off + 46, off + 46 + nameLen);
    entries.push({ name, method, compressedSize, size, localOffset });
    off += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

function readEntry(buf, entry) {
  const lo = entry.localOffset;
  if (buf.readUInt32LE(lo) !== SIG_LOCAL) throw new Error('zip: bad local header');
  const nameLen = buf.readUInt16LE(lo + 26);
  const extraLen = buf.readUInt16LE(lo + 28);
  const start = lo + 30 + nameLen + extraLen;
  const data = buf.subarray(start, start + entry.compressedSize);
  if (entry.method === 0) return Buffer.from(data);
  if (entry.method === 8) return zlib.inflateRawSync(data);
  throw new Error(`zip: unsupported compression method ${entry.method}`);
}

/** Returns a Map<name, Buffer> for the requested names (or all if none given). */
function extract(buf, names) {
  const want = names ? new Set(names) : null;
  const out = new Map();
  for (const e of listEntries(buf)) {
    if (e.name.endsWith('/')) continue;
    if (want && !want.has(e.name)) continue;
    out.set(e.name, readEntry(buf, e));
  }
  return out;
}

module.exports = { listEntries, extract };
