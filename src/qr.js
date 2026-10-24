'use strict';
// Dependency-free QR code encoder (byte mode, versions 1–40, EC levels L/M/Q/H)
// rendering to an SVG data URI. Based on the ISO/IEC 18004 algorithm.

const ECL = { L: { ord: 0, fmt: 1 }, M: { ord: 1, fmt: 0 }, Q: { ord: 2, fmt: 3 }, H: { ord: 3, fmt: 2 } };

// Indexed by [ecl.ord][version]
const ECC_PER_BLOCK = [
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
];
const NUM_BLOCKS = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
];

function numRawDataModules(ver) {
  let result = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const numAlign = Math.floor(ver / 7) + 2;
    result -= (25 * numAlign - 10) * numAlign - 55;
    if (ver >= 7) result -= 36;
  }
  return result;
}

function numDataCodewords(ver, ecl) {
  return Math.floor(numRawDataModules(ver) / 8) - ECC_PER_BLOCK[ecl.ord][ver] * NUM_BLOCKS[ecl.ord][ver];
}

// ---- GF(256) Reed–Solomon ---------------------------------------------------------------
function gfMul(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

function rsDivisor(degree) {
  const result = new Array(degree).fill(0);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < result.length; j++) {
      result[j] = gfMul(result[j], root);
      if (j + 1 < result.length) result[j] ^= result[j + 1];
    }
    root = gfMul(root, 0x02);
  }
  return result;
}

function rsRemainder(data, divisor) {
  const result = new Array(divisor.length).fill(0);
  for (const b of data) {
    const factor = b ^ result.shift();
    result.push(0);
    for (let j = 0; j < result.length; j++) result[j] ^= gfMul(divisor[j], factor);
  }
  return result;
}

// ---- bit buffer ----------------------------------------------------------------------------
function appendBits(bits, val, len) {
  for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
}

function encodeBytes(bytes, ecl) {
  let ver = 1;
  for (;;) {
    const cap = numDataCodewords(ver, ecl) * 8;
    const ccBits = ver <= 9 ? 8 : 16;
    if (4 + ccBits + bytes.length * 8 <= cap) break;
    if (ver === 40) throw new Error('QR: data too long');
    ver++;
  }
  const cap = numDataCodewords(ver, ecl) * 8;
  const bits = [];
  appendBits(bits, 0b0100, 4);
  appendBits(bits, bytes.length, ver <= 9 ? 8 : 16);
  for (const b of bytes) appendBits(bits, b, 8);
  appendBits(bits, 0, Math.min(4, cap - bits.length));
  appendBits(bits, 0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xec; bits.length < cap; pad ^= 0xec ^ 0x11) appendBits(bits, pad, 8);
  const data = [];
  for (let i = 0; i < bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
    data.push(b);
  }
  return { ver, data };
}

function addEccAndInterleave(data, ver, ecl) {
  const numBlocks = NUM_BLOCKS[ecl.ord][ver];
  const blockEccLen = ECC_PER_BLOCK[ecl.ord][ver];
  const rawCodewords = Math.floor(numRawDataModules(ver) / 8);
  const numShortBlocks = numBlocks - (rawCodewords % numBlocks);
  const shortBlockLen = Math.floor(rawCodewords / numBlocks);

  const blocks = [];
  const divisor = rsDivisor(blockEccLen);
  for (let i = 0, k = 0; i < numBlocks; i++) {
    const len = shortBlockLen - blockEccLen + (i < numShortBlocks ? 0 : 1);
    const dat = data.slice(k, k + len);
    k += len;
    const ecc = rsRemainder(dat, divisor);
    if (i < numShortBlocks) dat.push(0);
    blocks.push(dat.concat(ecc));
  }
  const result = [];
  for (let i = 0; i < blocks[0].length; i++) {
    for (let j = 0; j < blocks.length; j++) {
      if (i !== shortBlockLen - blockEccLen || j >= numShortBlocks) result.push(blocks[j][i]);
    }
  }
  return result;
}

// ---- matrix ---------------------------------------------------------------------------------
class Matrix {
  constructor(size) {
    this.size = size;
    this.modules = Array.from({ length: size }, () => new Array(size).fill(false));
    this.isFunction = Array.from({ length: size }, () => new Array(size).fill(false));
  }
  setFunction(x, y, dark) {
    this.modules[y][x] = dark;
    this.isFunction[y][x] = true;
  }
}

function alignmentPositions(ver) {
  if (ver === 1) return [];
  const numAlign = Math.floor(ver / 7) + 2;
  const size = ver * 4 + 17;
  // Version 32 is the one irregular case in the standard's alignment table.
  const step = ver === 32 ? 26 : Math.floor((ver * 4 + numAlign * 2 + 1) / (numAlign * 2 - 2)) * 2;
  const result = [6];
  for (let pos = size - 7; result.length < numAlign; pos -= step) result.splice(1, 0, pos);
  return result;
}

function drawFinder(m, x, y) {
  for (let dy = -4; dy <= 4; dy++) {
    for (let dx = -4; dx <= 4; dx++) {
      const dist = Math.max(Math.abs(dx), Math.abs(dy));
      const xx = x + dx, yy = y + dy;
      if (xx >= 0 && xx < m.size && yy >= 0 && yy < m.size) m.setFunction(xx, yy, dist !== 2 && dist !== 4);
    }
  }
}

function drawAlignment(m, x, y) {
  for (let dy = -2; dy <= 2; dy++) {
    for (let dx = -2; dx <= 2; dx++) m.setFunction(x + dx, y + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
}

function drawFormatBits(m, ecl, mask) {
  const data = (ecl.fmt << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const bits = ((data << 10) | rem) ^ 0x5412;
  const bit = (i) => ((bits >>> i) & 1) === 1;
  for (let i = 0; i <= 5; i++) m.setFunction(8, i, bit(i));
  m.setFunction(8, 7, bit(6));
  m.setFunction(8, 8, bit(7));
  m.setFunction(7, 8, bit(8));
  for (let i = 9; i < 15; i++) m.setFunction(14 - i, 8, bit(i));
  for (let i = 0; i < 8; i++) m.setFunction(m.size - 1 - i, 8, bit(i));
  for (let i = 8; i < 15; i++) m.setFunction(8, m.size - 15 + i, bit(i));
  m.setFunction(8, m.size - 8, true);
}

function drawVersion(m, ver) {
  if (ver < 7) return;
  let rem = ver;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
  const bits = (ver << 12) | rem;
  for (let i = 0; i < 18; i++) {
    const bit = ((bits >>> i) & 1) === 1;
    const a = m.size - 11 + (i % 3);
    const b = Math.floor(i / 3);
    m.setFunction(a, b, bit);
    m.setFunction(b, a, bit);
  }
}

function drawFunctionPatterns(m, ver, ecl) {
  for (let i = 0; i < m.size; i++) {
    m.setFunction(6, i, i % 2 === 0);
    m.setFunction(i, 6, i % 2 === 0);
  }
  drawFinder(m, 3, 3);
  drawFinder(m, m.size - 4, 3);
  drawFinder(m, 3, m.size - 4);
  const pos = alignmentPositions(ver);
  const n = pos.length;
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === n - 1) || (i === n - 1 && j === 0)) continue;
      drawAlignment(m, pos[i], pos[j]);
    }
  }
  drawFormatBits(m, ecl, 0);
  drawVersion(m, ver);
}

function drawCodewords(m, data) {
  let i = 0;
  const total = data.length * 8;
  for (let right = m.size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < m.size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? m.size - 1 - vert : vert;
        if (!m.isFunction[y][x] && i < total) {
          m.modules[y][x] = ((data[i >>> 3] >>> (7 - (i & 7))) & 1) === 1;
          i++;
        }
      }
    }
  }
}

function applyMask(m, mask) {
  for (let y = 0; y < m.size; y++) {
    for (let x = 0; x < m.size; x++) {
      let invert;
      switch (mask) {
        case 0: invert = (x + y) % 2 === 0; break;
        case 1: invert = y % 2 === 0; break;
        case 2: invert = x % 3 === 0; break;
        case 3: invert = (x + y) % 3 === 0; break;
        case 4: invert = (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; break;
        case 5: invert = ((x * y) % 2) + ((x * y) % 3) === 0; break;
        case 6: invert = (((x * y) % 2) + ((x * y) % 3)) % 2 === 0; break;
        default: invert = (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
      }
      if (!m.isFunction[y][x] && invert) m.modules[y][x] = !m.modules[y][x];
    }
  }
}

function penalty(m) {
  const n = m.size;
  let score = 0;
  const runPenalty = (runs) => {
    // finder-like pattern 1:1:3:1:1 with 4-light on either side
    let s = 0;
    for (let i = 0; i + 6 < runs.length; i++) {
      const [a, b, c, d, e] = runs.slice(i + 1, i + 6);
      if (b === a && c === 3 * a && d === a && e === a && (runs[i] >= 4 * a || runs[i + 6] >= 4 * a)) s += 40;
    }
    return s;
  };
  for (let y = 0; y < n; y++) {
    let runColor = m.modules[y][0], runLen = 1;
    const runs = [4];
    for (let x = 1; x <= n; x++) {
      if (x < n && m.modules[y][x] === runColor) runLen++;
      else {
        if (runLen >= 5) score += 3 + (runLen - 5);
        runs.push(runLen);
        runColor = x < n ? m.modules[y][x] : runColor;
        runLen = 1;
      }
    }
    runs.push(4);
    score += runPenalty(runs);
  }
  for (let x = 0; x < n; x++) {
    let runColor = m.modules[0][x], runLen = 1;
    const runs = [4];
    for (let y = 1; y <= n; y++) {
      if (y < n && m.modules[y][x] === runColor) runLen++;
      else {
        if (runLen >= 5) score += 3 + (runLen - 5);
        runs.push(runLen);
        runColor = y < n ? m.modules[y][x] : runColor;
        runLen = 1;
      }
    }
    runs.push(4);
    score += runPenalty(runs);
  }
  for (let y = 0; y < n - 1; y++) {
    for (let x = 0; x < n - 1; x++) {
      const c = m.modules[y][x];
      if (c === m.modules[y][x + 1] && c === m.modules[y + 1][x] && c === m.modules[y + 1][x + 1]) score += 3;
    }
  }
  let dark = 0;
  for (const row of m.modules) for (const c of row) if (c) dark++;
  const total = n * n;
  const k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
  score += k * 10;
  return score;
}

/** Encode text → boolean matrix (true = dark). */
function encode(text, level = 'M') {
  const ecl = ECL[level] || ECL.M;
  const bytes = Array.from(Buffer.from(text, 'utf8'));
  const { ver, data } = encodeBytes(bytes, ecl);
  const codewords = addEccAndInterleave(data, ver, ecl);
  const m = new Matrix(ver * 4 + 17);
  drawFunctionPatterns(m, ver, ecl);
  drawCodewords(m, codewords);

  let best = -1, bestScore = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    applyMask(m, mask);
    drawFormatBits(m, ecl, mask);
    const s = penalty(m);
    if (s < bestScore) { bestScore = s; best = mask; }
    applyMask(m, mask); // undo (XOR)
  }
  applyMask(m, best);
  drawFormatBits(m, ecl, best);
  return m.modules;
}

/** Encode text → SVG string with a 4-module quiet zone. */
function toSvg(text, { level = 'M', scale = 6, dark = '#000', light = '#fff' } = {}) {
  const modules = encode(text, level);
  const n = modules.length;
  const border = 4;
  const dim = (n + border * 2) * scale;
  let d = '';
  for (let y = 0; y < n; y++) {
    for (let x = 0; x < n; x++) {
      if (modules[y][x]) d += `M${(x + border) * scale} ${(y + border) * scale}h${scale}v${scale}h-${scale}z`;
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${dim} ${dim}" width="${dim}" height="${dim}" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="${light}"/><path d="${d}" fill="${dark}"/></svg>`;
}

function toDataUri(text, opts) {
  return 'data:image/svg+xml;base64,' + Buffer.from(toSvg(text, opts)).toString('base64');
}

module.exports = { encode, toSvg, toDataUri };
