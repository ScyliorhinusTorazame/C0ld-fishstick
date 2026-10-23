/*!
 * sft-core.js — SFTA v2 容器格式
 * 字节分片(4MiB) + PBKDF2-SHA256(600k) + AES-256-GCM
 * 零第三方依赖；浏览器直接 <script> 引入即可，Node 下可 require 做自测。
 *
 * 文件布局：
 *   [0..4)   "SFTA"
 *   [4]      version = 2
 *   [5..9)   headerLen (u32 BE)
 *   [9..)    明文 header(JSON) —— 只含 KDF 参数与 meta 的偏移，不含文件名
 *   [..)     meta 密文(AES-GCM, AAD="SFTA2META") —— 条目名/类型/大小/块数
 *   [..)     body：逐块记录 = iv(12) | ctLen(u32) | ciphertext+tag(16)
 *            AAD = "SFTA2CHNK" | entryIdx(u32) | chunkIdx(u32) | chunkCount(u32)
 */
(function (root) {
  'use strict';

  var MAGIC_STR = 'SFTA';
  var VERSION = 2;
  var CHUNK_SIZE = 4 * 1024 * 1024;
  var DEFAULT_ITERS = 600000;
  var MIN_ITERS = 100000;
  var MAX_ITERS = 2000000;
  var MAX_CHUNK_SIZE = 64 * 1024 * 1024;
  var MAX_HEADER_LEN = 8000;

  var META_AAD = ascii('SFTA2META');
  var CHUNK_TAG = ascii('SFTA2CHNK');

  var ERR = {
    UNSUPPORTED: 'UNSUPPORTED',
    BAD_INPUT: 'BAD_INPUT',
    BAD_FORMAT: 'BAD_FORMAT',
    BAD_VERSION: 'BAD_VERSION',
    DECRYPT_FAILED: 'DECRYPT_FAILED',
    INCOMPLETE: 'INCOMPLETE'
  };

  class SftError extends Error {
    constructor(code, message) {
      super(message || code);
      this.name = 'SftError';
      this.code = code;
    }
  }

  /* ---------------- 基础工具 ---------------- */

  function ascii(s) {
    var a = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) a[i] = s.charCodeAt(i) & 0xff;
    return a;
  }

  function getSubtle() {
    var c = (typeof crypto !== 'undefined') ? crypto : null;
    if (!c || !c.subtle) {
      throw new SftError(ERR.UNSUPPORTED, '当前环境不支持 WebCrypto（页面必须通过 https 或 localhost 打开）');
    }
    return c.subtle;
  }

  function randomBytes(n) {
    if (typeof crypto === 'undefined' || !crypto.getRandomValues) {
      throw new SftError(ERR.UNSUPPORTED, '当前环境没有安全随机数发生器');
    }
    var b = new Uint8Array(n);
    crypto.getRandomValues(b);
    return b;
  }

  function u32(n) {
    var b = new Uint8Array(4);
    b[0] = (n >>> 24) & 0xff; b[1] = (n >>> 16) & 0xff;
    b[2] = (n >>> 8) & 0xff; b[3] = n & 0xff;
    return b;
  }

  function rdU32(b, o) {
    return (((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0);
  }

  function b64enc(u8) {
    var s = '', N = 0x8000;
    for (var i = 0; i < u8.length; i += N) {
      s += String.fromCharCode.apply(null, u8.subarray(i, i + N));
    }
    return btoa(s);
  }

  function b64dec(str) {
    var bin = atob(str), u8 = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    return u8;
  }

  function chunkAad(entryIdx, chunkIdx, chunkCount) {
    var a = new Uint8Array(18);
    a.set(CHUNK_TAG, 0);
    var dv = new DataView(a.buffer);
    dv.setUint32(6, entryIdx);
    dv.setUint32(10, chunkIdx);
    dv.setUint32(14, chunkCount);
    return a;
  }

  function yieldToUI() {
    return new Promise(function (r) { setTimeout(r, 0); });
  }

  function toBlobPart(buf) {
    return buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  }

  /* ---------------- 密钥派生 ---------------- */

  async function deriveKey(passphrase, salt, iterations) {
    var st = getSubtle();
    var base = await st.importKey(
      'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']
    );
    return st.deriveKey(
      { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /* ---------------- 加密打包 ---------------- */

  /**
   * @param {Array<{name:string,type:string,blob:Blob}>} items
   * @param {string} passphrase
   * @param {(p:object)=>void} [onProgress]
   * @returns {Promise<Blob>}
   */
  async function pack(items, passphrase, onProgress) {
    var st = getSubtle();
    if (!Array.isArray(items) || items.length === 0) {
      throw new SftError(ERR.BAD_INPUT, '没有要加密的文件');
    }
    if (typeof passphrase !== 'string' || passphrase.length === 0) {
      throw new SftError(ERR.BAD_INPUT, '密钥不能为空');
    }

    var salt = randomBytes(16);
    if (onProgress) onProgress({ phase: 'kdf', label: '正在派生密钥…' });
    var key = await deriveKey(passphrase, salt, DEFAULT_ITERS);

    var entries = items.map(function (it) {
      return {
        name: String((it && it.name) || 'file'),
        type: String((it && it.type) || ''),
        size: it.blob.size,
        chunkCount: Math.max(1, Math.ceil(it.blob.size / CHUNK_SIZE))
      };
    });

    var meta = { createdAt: Date.now(), chunkSize: CHUNK_SIZE, entries: entries };
    var metaIv = randomBytes(12);
    var metaPlain = new TextEncoder().encode(JSON.stringify(meta));
    var metaCt = new Uint8Array(await st.encrypt(
      { name: 'AES-GCM', iv: metaIv, additionalData: META_AAD, tagLength: 128 },
      key, metaPlain
    ));

    var header = {
      v: VERSION,
      c: 'AES-256-GCM',
      cs: CHUNK_SIZE,
      kdf: { alg: 'PBKDF2-SHA256', it: DEFAULT_ITERS, salt: b64enc(salt) },
      miv: b64enc(metaIv),
      mn: metaCt.length
    };
    var headerBytes = new TextEncoder().encode(JSON.stringify(header));

    var parts = [ascii(MAGIC_STR), new Uint8Array([VERSION]), u32(headerBytes.length), headerBytes, metaCt];

    var totalChunks = entries.reduce(function (s, e) { return s + e.chunkCount; }, 0);
    var totalBytes = entries.reduce(function (s, e) { return s + e.size; }, 0);
    var chunkDone = 0, bytesDone = 0;

    for (var ei = 0; ei < items.length; ei++) {
      var blob = items[ei].blob;
      var n = entries[ei].chunkCount;
      for (var ci = 0; ci < n; ci++) {
        var start = ci * CHUNK_SIZE;
        var end = Math.min(start + CHUNK_SIZE, blob.size);
        var plain = await blob.slice(start, end).arrayBuffer();
        var iv = randomBytes(12);
        var ct = new Uint8Array(await st.encrypt(
          { name: 'AES-GCM', iv: iv, additionalData: chunkAad(ei, ci, n), tagLength: 128 },
          key, plain
        ));
        // 立即转成 Blob 再放进数组：Blob 由浏览器托管（可落盘），
        // 避免把整份密文以 Uint8Array 形式留在 JS 堆里，这是大文件不 OOM 的关键。
        parts.push(new Blob([iv, u32(ct.length), ct]));

        chunkDone++;
        bytesDone += (end - start);
        if (onProgress) {
          onProgress({
            phase: 'encrypt',
            fileName: entries[ei].name,
            chunkDone: chunkDone,
            totalChunks: totalChunks,
            bytesDone: bytesDone,
            totalBytes: totalBytes
          });
        }
        await yieldToUI();
      }
    }

    return new Blob(parts, { type: 'application/octet-stream' });
  }

  /* ---------------- 解密解包 ---------------- */

  /**
   * @param {Blob} blob  .sft 文件
   * @param {string} passphrase
   * @param {(p:object)=>void} [onProgress]
   * @returns {Promise<{entries:Array<{name:string,type:string,size:number,blob:Blob}>, createdAt:number}>}
   */
  async function unpack(blob, passphrase, onProgress) {
    var st = getSubtle();
    if (!blob || typeof blob.size !== 'number') {
      throw new SftError(ERR.BAD_INPUT, '没有选择文件');
    }
    if (typeof passphrase !== 'string' || passphrase.length === 0) {
      throw new SftError(ERR.BAD_INPUT, '密钥不能为空');
    }
    if (blob.size < 9) {
      throw new SftError(ERR.BAD_FORMAT, '文件太小，不是有效的 .sft 文件');
    }

    var head = new Uint8Array(await blob.slice(0, 9).arrayBuffer());
    var magic = '';
    for (var i = 0; i < 4; i++) magic += String.fromCharCode(head[i]);
    if (magic !== MAGIC_STR) {
      throw new SftError(ERR.BAD_FORMAT, '不是有效的 .sft 文件（文件头不匹配，可能选错了文件）');
    }
    var ver = head[4];
    if (ver !== VERSION) {
      throw new SftError(ERR.BAD_VERSION, '文件版本 v' + ver + ' 不受支持（本页仅支持 v' + VERSION + '）');
    }

    var headerLen = rdU32(head, 5);
    if (headerLen < 2 || headerLen > MAX_HEADER_LEN || 9 + headerLen > blob.size) {
      throw new SftError(ERR.BAD_FORMAT, '文件头损坏');
    }

    var header;
    try {
      header = JSON.parse(new TextDecoder().decode(
        new Uint8Array(await blob.slice(9, 9 + headerLen).arrayBuffer())
      ));
    } catch (e) {
      throw new SftError(ERR.BAD_FORMAT, '文件头无法解析');
    }
    if (!header || header.v !== VERSION) throw new SftError(ERR.BAD_FORMAT, '文件头版本不一致');

    var kdf = header.kdf || {};
    var iters = Number(kdf.it);
    if (kdf.alg !== 'PBKDF2-SHA256') throw new SftError(ERR.BAD_FORMAT, '不支持的密钥派生算法');
    if (!Number.isInteger(iters) || iters < MIN_ITERS || iters > MAX_ITERS) {
      throw new SftError(ERR.BAD_FORMAT, '不支持的密钥派生参数');
    }
    var cs = Number(header.cs);
    if (!Number.isInteger(cs) || cs <= 0 || cs > MAX_CHUNK_SIZE) {
      throw new SftError(ERR.BAD_FORMAT, '不支持的分片大小');
    }
    var salt, metaIv;
    try {
      salt = b64dec(String(kdf.salt));
      metaIv = b64dec(String(header.miv));
    } catch (e) {
      throw new SftError(ERR.BAD_FORMAT, '文件头损坏');
    }
    if (salt.length < 8 || metaIv.length !== 12) throw new SftError(ERR.BAD_FORMAT, '文件头损坏');

    var metaLen = Number(header.mn);
    if (!Number.isInteger(metaLen) || metaLen < 16) throw new SftError(ERR.BAD_FORMAT, '文件头损坏');

    var metaStart = 9 + headerLen;
    var bodyStart = metaStart + metaLen;
    if (bodyStart > blob.size) throw new SftError(ERR.INCOMPLETE, '文件不完整（可能在传输中被截断）');

    if (onProgress) onProgress({ phase: 'kdf', label: '正在派生密钥…' });
    var key = await deriveKey(passphrase, salt, iters);

    var meta;
    try {
      var metaPlain = await st.decrypt(
        { name: 'AES-GCM', iv: metaIv, additionalData: META_AAD, tagLength: 128 },
        key,
        await blob.slice(metaStart, bodyStart).arrayBuffer()
      );
      meta = JSON.parse(new TextDecoder().decode(metaPlain));
    } catch (e) {
      throw new SftError(ERR.DECRYPT_FAILED, '密钥错误，或文件已损坏/被修改');
    }
    if (!meta || !Array.isArray(meta.entries) || meta.entries.length === 0) {
      throw new SftError(ERR.BAD_FORMAT, '元数据损坏');
    }

    var totalChunks = meta.entries.reduce(function (s, e) { return s + (e.chunkCount || 0); }, 0);
    var totalBytes = meta.entries.reduce(function (s, e) { return s + (e.size || 0); }, 0);
    var off = bodyStart, chunkDone = 0, bytesDone = 0;
    var out = [];

    for (var ei = 0; ei < meta.entries.length; ei++) {
      var e = meta.entries[ei];
      var n = e.chunkCount;
      if (!Number.isInteger(n) || n < 1 || n > 1000000) throw new SftError(ERR.BAD_FORMAT, '元数据损坏');

      var blobs = [];
      for (var ci = 0; ci < n; ci++) {
        if (off + 16 > blob.size) throw new SftError(ERR.INCOMPLETE, '文件不完整（可能在传输中被截断）');
        var rec = new Uint8Array(await blob.slice(off, off + 16).arrayBuffer());
        var iv = rec.slice(0, 12);
        var len = rdU32(rec, 12);
        if (len < 16 || off + 16 + len > blob.size) {
          throw new SftError(ERR.INCOMPLETE, '文件不完整（数据块长度异常）');
        }
        var ctBuf = await blob.slice(off + 16, off + 16 + len).arrayBuffer();
        off += 16 + len;

        var pt;
        try {
          pt = await st.decrypt(
            { name: 'AES-GCM', iv: iv, additionalData: chunkAad(ei, ci, n), tagLength: 128 },
            key, ctBuf
          );
        } catch (err) {
          throw new SftError(ERR.DECRYPT_FAILED, '数据块校验失败：密钥不对，或文件被改动/损坏');
        }
        blobs.push(new Blob([toBlobPart(pt)]));

        chunkDone++;
        bytesDone += pt.byteLength;
        if (onProgress) {
          onProgress({
            phase: 'decrypt',
            fileName: e.name,
            chunkDone: chunkDone,
            totalChunks: totalChunks,
            bytesDone: bytesDone,
            totalBytes: totalBytes
          });
        }
        await yieldToUI();
      }

      out.push({
        name: e.name,
        type: e.type || '',
        size: e.size,
        blob: new Blob(blobs, { type: e.type || 'application/octet-stream' })
      });
    }

    return { entries: out, createdAt: meta.createdAt || 0 };
  }

  /* ---------------- 导出 ---------------- */

  function chunkCountFor(size) {
    return Math.max(1, Math.ceil(size / CHUNK_SIZE));
  }

  var API = {
    pack: pack,
    unpack: unpack,
    deriveKey: deriveKey,
    chunkCountFor: chunkCountFor,
    SftError: SftError,
    ERR: ERR,
    CHUNK_SIZE: CHUNK_SIZE,
    DEFAULT_ITERS: DEFAULT_ITERS,
    VERSION: VERSION
  };

  root.SFT = API;
  if (typeof module !== 'undefined' && module.exports) module.exports = API;
})(typeof globalThis !== 'undefined' ? globalThis : this);
