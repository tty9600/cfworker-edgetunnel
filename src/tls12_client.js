//  A simple TLSv1.2 client implementation based on NodeJS/JavaScript.
//
//  Copyright (C) 2026 - Public Free Software
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <https://www.gnu.org/licenses/>.

//  NOTE: signature verification for Certificates and KeyExchange
//        is not currently supported.
//
//  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   0xc02f (49199)
//  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   0xc030 (49200)
//  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0xc02b (49195)
//  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 0xc02c (49196)
//  RSA_PSS_RSAE_SHA256    0x0804 (2052)
//  RSA_PSS_RSAE_SHA384    0x0805 (2053)
//  RSA_PSS_RSAE_SHA512    0x0806 (2054)
//  RSA_PKCS1_SHA256       0x0401 (1025)
//  RSA_PKCS1_SHA384       0x0501 (1281)
//  RSA_PKCS1_SHA512       0x0601 (1537)
//  ECDSA_SECP256R1_SHA256 0x0403 (1027)
//  ECDSA_SECP384R1_SHA384 0x0503 (1283)
//  ECDSA_SECP521R1_SHA512 0x0603 (1539)
//  X25519    0x001d (29)
//  SECP256R1 0x0017 (23)

const uint24be = (x) => (x&0xff)<<16|(x&0xff00)|(x&0xff0000)>>16;
const uint16be = (x) => (x&0xff)<<8|(x&0xff00)>>8;
const uint16bearr8 = (arr) => new Uint8Array(new Uint16Array(arr).map(uint16be).buffer);
const uint24beget = (arr) => uint24be(arr[0]|arr[1]<<8|arr[2]<<16);
const uint16beget = (arr) => new DataView(arr.buffer).getUint16(0);
const textencode = (str) => new TextEncoder().encode(str);
const textdecode = (str) => new TextDecoder().decode(str);
const get_random = (length) => crypto.getRandomValues(new Uint8Array(length));
const chunkscat_arr8 = (...chunks) => {
  const of_chunks = chunks.filter((chunk) => chunk && chunk.length > 0);
  const length = of_chunks.reduce((total, chunk) => total + chunk.length, 0);
  const buffer = new Uint8Array(length); let offset = 0;
  for (const chunk of of_chunks) {
    buffer.set(chunk, offset); offset += chunk.length;
  } return buffer;
};
const constant_time_eq = (a, b) => {
  if (!a || !b || a.length !== b.length) return false;
  let x = 0; for (let i = 0; i < a.length; i++) x |= a[i] ^ b[i];
  return !!((x - 1) >> 8);
};

function build_client_record(payload, type) {
  let offset = 0; const record = new Uint8Array(payload.length + 5);
  record.set([ type ], offset); offset += 1; /* content type */
  record.set([ 0x03, 0x03 ], offset); offset += 2; /* version tls1.2 */
  record.set(uint16bearr8([ payload.length ]), offset); /* payload length */
  offset += 2; record.set(payload, offset); offset += payload.length;
  return { record: record, payload: payload };
}

function build_client_handshake(body, type) {
  let offset = 0; const handshake = new Uint8Array(body.length + 4);
  handshake.set([ type ], offset); offset += 2; /* handshake type */
  handshake.set(uint16bearr8([ body.length ]), offset); /* body length (3-bytes) */
  offset += 2; handshake.set(body, offset); offset += body.length;
  return handshake;
}

function build_client_hello({ randbyets = null, sni = null, alpn = null }) {
  if (!randbyets) throw new Error("TLS Random Bytes is empty value");
  if (randbyets.length < 32) throw new Error("TLS Random Bytes < 32-bytes");
  let offset = 0; const hello = new Uint8Array(4096);
  hello.set([ 0x03, 0x03 ], offset); offset += 2; /* version tls1.2 */
  hello.set(randbyets.slice(0, 32), offset); offset += 32; /* random bytes */
  hello.set([ 0 ], offset); offset += 1; /* session length */
  hello.set(uint16bearr8([ 8 ]), offset); offset += 2; /* cipher suite list */
  hello.set(uint16bearr8([ 0xc02f, 0xc030, 0xc02b, 0xc02c ]), offset); offset += 8;
  hello.set([ 1, 0 ], offset); offset += 2; /* compression */
  const ext_offset = offset += 2;
  /* Server Name / SNI */
  if (sni) {
    const snibuf = textencode(sni);
    hello.set(uint16bearr8([ 0x00, snibuf.length + 5 ]), offset); offset += 4;
    hello.set(uint16bearr8([ snibuf.length + 3 ]), offset); offset += 2;
    hello.set([ 0x00 ], offset); offset += 1;
    hello.set(uint16bearr8([ snibuf.length ]), offset); offset += 2;
    hello.set(snibuf, offset); offset += snibuf.length;
  }
  /* EC Point Formats */
  hello.set(uint16bearr8([ 0x0b, 2 ]), offset); offset += 4;
  hello.set([ 0x01, 0x00 ], offset); offset += 2;
  /* Supported Groups */
  hello.set(uint16bearr8([ 0x0a, 6 ]), offset); offset += 4;
  hello.set(uint16bearr8([ 4 ]), offset); offset += 2;
  hello.set(uint16bearr8([ 0x1d, 0x17 ]), offset); offset += 4;
  /* Signature Algorithms */
  hello.set(uint16bearr8([ 0x0d, 20 ]), offset); offset += 4;
  hello.set(uint16bearr8([ 18 ]), offset); offset += 2;
  hello.set(uint16bearr8([ 0x0804, 0x0805, 0x0806,
    0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0603 ]), offset); offset += 18;
  /* ALPN */
  if (alpn) {
    const alpn_offset = offset += 6;
    if (!Array.isArray(alpn)) alpn = [ alpn ];
    for (const str of alpn) {
      const buf = textencode(str);
      hello.set([ buf.length ], offset); offset += 1;
      hello.set(buf, offset); offset += buf.length;
    }
    hello.set(uint16bearr8([ 0x10, offset - alpn_offset + 2 ]), alpn_offset - 6);
    hello.set(uint16bearr8([ offset - alpn_offset ]), alpn_offset - 2);
  }
  hello.set(uint16bearr8([ offset - ext_offset ]), ext_offset - 2); /* extensions */
  const handshake = build_client_handshake(hello.slice(0, offset), 0x01);
  return build_client_record(handshake, 0x16);
}

function parse_server_handshake(payload) {
  const buffer = new Uint8Array(payload);
  const type = buffer[0]; /* handshake type */
  const length = uint24beget(buffer.slice(1));
  const body = buffer.slice(4, length + 4);
  return { type: type, body: body };
}

function parse_server_hello(body) {
  let offset = 2, alpn = null;
  if (body[0] != 0x03 || body[1] != 0x03) /* version tls1.2 */
    throw new Error("TLS Server Hello version is not tls1.2 error");
  const randbyets = body.slice(offset, offset + 32); offset += 32; /* random bytes */
  offset += body[offset] + 1; /* session length */
  const cipher = uint16beget(body.slice(offset)); offset += 2; /* cipher suite */
  if (!new Map([ [ 0xc02f, 1 ], [ 0xc030, 1 ], [ 0xc02b, 1 ], [ 0xc02c, 1 ] ])
      .get(cipher)) throw new Error("TLS Server cipher suite error");
  if (body[offset++] != 0) throw new Error("TLS Server compression error");
  const ext_length = uint16beget(body.slice(offset)); offset += 2; /* extensions */
  const ext_end = offset + ext_length;
  while ((offset + 4) <= ext_end) {
    const type = uint16beget(body.slice(offset)); offset += 2;
    const length = uint16beget(body.slice(offset)); offset += 2;
    const data = body.slice(offset, offset + length); offset += length;
    if (type == 0x10 && length >= 3) { /* alpn */
      alpn = textdecode(data.slice(3));
    }
  } return { randbyets: randbyets, cipher: cipher, alpn: alpn };
}

function parse_server_certs(body) {
  let offset = 0, certs = [];
  if (body.length >= 3) {
    const cert_length = uint24beget(body.slice(offset)); offset += 3;
    const cert_end = offset + cert_length;
    while ((offset + 3) <= cert_end) {
      const length = uint24beget(body.slice(offset)); offset += 3;
      const data = body.slice(offset, offset + length); offset += length;
      certs.push(data);
    }
  } return { certs: certs };
}

function parse_server_ecdhe(body) {
  let offset = 1;
  const ecdh_alg = uint16beget(body.slice(offset)); offset += 2;
  const ecdh_pub_length = body[offset++];
  const ecdh_pub = body.slice(offset, offset + ecdh_pub_length);
  offset += ecdh_pub_length;
  const sign_alg = uint16beget(body.slice(offset)); offset += 2;
  const sign_length = uint16beget(body.slice(offset)); offset += 2;
  const sign = body.slice(offset, offset + sign_length); offset += sign_length;
  return { ecdh_alg: ecdh_alg, ecdh_pub: ecdh_pub, sign_alg: sign_alg, sign: sign };
}

function tls12_cipher_mapget(cipher) {
  return new Map([
    [ 0xc02f, { id: 0xc02f, keylen: 16, ivlen: 4, hash: "SHA-256" } ],
    [ 0xc030, { id: 0xc030, keylen: 32, ivlen: 4, hash: "SHA-384" } ],
    [ 0xc02b, { id: 0xc02b, keylen: 16, ivlen: 4, hash: "SHA-256" } ],
    [ 0xc02c, { id: 0xc02c, keylen: 32, ivlen: 4, hash: "SHA-384" } ]
    ]).get(cipher);
}

function tls12_alg_mapget(alg) {
  return new Map([ [ 0x1d, { name: "X25519" } ],
    [ 0x17, { name: "ECDH", namedCurve: "P-256" } ] ]).get(alg);
}

async function tls12_generate_keypair(alg) {
  alg = tls12_alg_mapget(alg);
  if (!alg) throw new Error("TLS generate_keypair() algorithm error");
  const keypair = await crypto.subtle.generateKey(alg, true, [ "deriveBits" ]);
  // @ts-ignore
  const pubraw = await crypto.subtle.exportKey("raw", keypair.publicKey);
  // @ts-ignore
  return { keypair: keypair, pubraw: new Uint8Array(pubraw) };
}

async function tls12_generate_sharedkey(alg, keypair, perr_pubraw) {
  alg = tls12_alg_mapget(alg);
  if (!alg) throw new Error("TLS generate_sharedkey() algorithm error");
  const perr_pub = await crypto.subtle.importKey("raw", perr_pubraw, alg, false, []);
  return new Uint8Array(await crypto.subtle.deriveBits(
    // @ts-ignore
    { name: alg.name, public: perr_pub }, keypair.keypair.privateKey, 256));
}

async function tls12_hmac(key, data, cipher) {
  cipher = tls12_cipher_mapget(cipher);
  if (!cipher) throw new Error("TLS hmac() cipher suite error");
  key = await crypto.subtle.importKey("raw", key,
    { name: "HMAC", hash: cipher.hash }, false, [ "sign" ] );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
}

async function tls12_digest(data, cipher) {
  cipher = tls12_cipher_mapget(cipher);
  if (!cipher) throw new Error("TLS digest() cipher suite error");
  return new Uint8Array(await crypto.subtle.digest(cipher.hash, data));
}

async function tls12_prf(secret, label, seed, length, cipher) {
  const label_seed = chunkscat_arr8(textencode(label), seed);
  let output = new Uint8Array(0), current = label_seed;
  while (output.length < length) {
    current = await tls12_hmac(secret, current, cipher);
    const block = await tls12_hmac(secret, chunkscat_arr8(current, label_seed), cipher);
    output = chunkscat_arr8(output, block);
  } return output.slice(0, length);
}

async function tls12_aesgcm_keypair(encrypt_keyraw, decrypt_keyraw) {
  const encrypt = await crypto.subtle.importKey("raw", encrypt_keyraw,
    { name: "AES-GCM" }, false, [ "encrypt" ]);
  const decrypt = await crypto.subtle.importKey("raw", decrypt_keyraw,
    { name: "AES-GCM" }, false, [ "decrypt" ]);
  return { encrypt: encrypt, decrypt: decrypt };
}

async function tls12_aesgcm_encrypt(keypair, iv, plaintext, aad) {
  return new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv, additionalData: aad, tagLength: 128 },
    keypair.encrypt, plaintext));
}

async function tls12_aesgcm_decrypt(keypair, iv, ciphertext, aad) {
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv, additionalData: aad, tagLength: 128 },
    keypair.decrypt, ciphertext));
}

class tls12_record_reader {
  constructor() { this.buffer = new Uint8Array(0); }
  put(chunk) {
    this.buffer = chunkscat_arr8(this.buffer, new Uint8Array(chunk));
  }
  get() {
    const buffer = this.buffer; if (buffer.length < 5) return null;
    const type = buffer[0];
    const version = uint16beget(buffer.slice(1));
    const length = uint16beget(buffer.slice(3));
    if (buffer.length < (length + 5)) return null;
    const payload = buffer.slice(5, length + 5);
    this.buffer = buffer.slice(length + 5);
    return { type: type, version: version, payload: payload };
  }
}

export class TLS12_Client {
  constructor(socket, options = {}) {
    this.socket = socket;
    this.sni = options.sni || "";
    this.alpn = options.alpn || "http/1.1";
    this.client_randbyets = get_random(32);
    this.server_hello = null;
    this.server_certs = null;
    this.server_ecdhe = null;
    this.server_done = false;
    this.record_reader = new tls12_record_reader();
    this.handshake_client_hello = null;
    this.handshake_server_hello = null;
    this.handshake_server_certs = null;
    this.handshake_server_ecdhe = null;
    this.handshake_server_done = null;
    this.handshake_client_ecdhe = null;
    this.handshake_client_finished = null;
    this.ecdhe_keypair = null;
    this.crypto_keypair = null;
    this.encrypt_iv = null;
    this.decrypt_iv = null;
    this.client_seq = 0n;
    this.server_seq = 0n;
    this.handshake_ok = true;
  }

  transcript() {
    return chunkscat_arr8(
     this.handshake_client_hello, this.handshake_server_hello,
     this.handshake_server_certs, this.handshake_server_ecdhe,
     this.handshake_server_done, this.handshake_client_ecdhe,
     this.handshake_client_finished);
  }

  async handshake() {
    console.log(`TLS handshake sni:${this.sni} alpn:${this.alpn}`);
    const reader = this.socket.readable.getReader();
    const writer = this.socket.writable.getWriter();
    try {
      const hello = build_client_hello(
        { randbyets: this.client_randbyets, sni: this.sni, alpn: this.alpn });
      this.handshake_client_hello = hello.payload;
      await writer.write(hello.record);
      await this.receive_server_hello(reader);
      await this.tls12_handshake(reader, writer);
    } finally { reader.releaseLock(); writer.releaseLock(); }
  }

  async receive_server_hello(reader) {
    await this.receive_server_until(reader,
      async (record) => {
        const payload = record.payload;
        if (record.type != 0x16)
          throw new Error(`TLS record is not handshake type: ${record.type}`);
        const res = parse_server_handshake(payload);
        if (res.type == 0x02) {
          if (this.handshake_server_hello)
            throw new Error("TLS Server Hello repeated");
          console.log("TLS handshake Server Hello");
          this.server_hello = parse_server_hello(res.body);
          this.handshake_server_hello = payload;
        } else if (res.type == 0x0b) {
          if (this.handshake_server_certs)
            throw new Error("TLS Server Certificate repeated");
          console.log("TLS handshake Server Certificate");
          this.server_certs = parse_server_certs(res.body);
          this.handshake_server_certs = payload;
        } else if (res.type == 0x0c) {
          if (this.handshake_server_ecdhe)
            throw new Error("TLS Server KeyExchange repeated");
          console.log("TLS handshake Server KeyExchange");
          this.server_ecdhe = parse_server_ecdhe(res.body);
          this.handshake_server_ecdhe = payload;
        } else if (res.type == 0x0e) {
          console.log("TLS handshake Server HelloDone");
          this.server_done = true;
          this.handshake_server_done = payload;
          return true;
        } else {
          throw new Error(`TLS unexpected handshake type: ${res.type}`);
        }
      });
    console.log("TLS handshake", `cipher_suite:${this.server_hello.cipher}`,
      `ecdh_alg:${this.server_ecdhe.ecdh_alg}`, `sign_alg:${this.server_ecdhe.sign_alg}`,
      `alpn:${this.server_hello.alpn}`);
  }

  async tls12_handshake(reader, writer) {
    const ecdhe_keypair = await tls12_generate_keypair(this.server_ecdhe.ecdh_alg);
    const sharedkey = await tls12_generate_sharedkey(
      this.server_ecdhe.ecdh_alg, ecdhe_keypair, this.server_ecdhe.ecdh_pub);
    const client_ecdhe = build_client_record(build_client_handshake(chunkscat_arr8(
      [ ecdhe_keypair.pubraw.length ], ecdhe_keypair.pubraw), 0x10), 0x16);
    this.handshake_client_ecdhe = client_ecdhe.payload;
    this.ecdhe_keypair = ecdhe_keypair;
    const cipher = tls12_cipher_mapget(this.server_hello.cipher);
    const master_secret = await tls12_prf(sharedkey, "master secret",
      chunkscat_arr8(this.client_randbyets, this.server_hello.randbyets),
      48, cipher.id);
    const keyblock = await tls12_prf(master_secret, "key expansion",
      chunkscat_arr8(this.server_hello.randbyets, this.client_randbyets),
      cipher.keylen * 2 + cipher.ivlen * 2, cipher.id);
    this.crypto_keypair = await tls12_aesgcm_keypair(keyblock.slice(0, cipher.keylen),
      keyblock.slice(cipher.keylen, cipher.keylen * 2));
    this.encrypt_iv = keyblock.slice(cipher.keylen * 2,
      cipher.keylen * 2 + cipher.ivlen);
    this.decrypt_iv = keyblock.slice(cipher.keylen * 2 + cipher.ivlen,
      cipher.keylen * 2 + cipher.ivlen * 2);
    const client_verify_data = await tls12_prf(master_secret, "client finished",
      await tls12_digest(this.transcript(), cipher.id), 12, cipher.id);
    const client_finished = build_client_handshake(client_verify_data, 0x14);
    this.handshake_client_finished = client_finished;
    console.log("TLS handshake Client KeyExchange");
    await writer.write(client_ecdhe.record);
    console.log("TLS handshake Client CipherSpec");
    await writer.write(build_client_record([ 0x01 ], 0x14).record);
    console.log("TLS handshake Client Finished");
    await writer.write(build_client_record(
      await this.tls12_encrypt(client_finished, 0x16), 0x16).record);
    await this.receive_server_until(reader,
      async (record) => {
        const payload = record.payload;
        if (record.type == 0x14) {
          console.log("TLS handshake Server CipherSpec"); return false;
        }
        if (record.type != 0x16)
          throw new Error(`TLS record is not handshake type: ${record.type}`);
        const plaintext = await this.tls12_decrypt(record.payload, 0x16);
        const res = parse_server_handshake(plaintext);
        if (res.type == 0x14) {
          console.log("TLS handshake Server Finished");
          const server_verify_data = await tls12_prf(master_secret, "server finished",
            await tls12_digest(this.transcript(), cipher.id), 12, cipher.id);
          if (!constant_time_eq(res.body, server_verify_data))
            throw new Error("TLS Server Finished verify failed");
          this.handshake_ok = true; return true;
        } else { throw new Error(`TLS unexpected handshake type: ${res.type}`); }
      });
    console.log("TLS handshake OK!");
  }

  async read_chunk(reader) { return reader.read(); }

  async receive_server_until(reader, predicate) {
    while (true) {
      while (true) {
        const record = this.record_reader.get(); if (!record) break;
        const payload = record.payload;
        if (record.type == 0x15)
          throw new Error(`TLS Alert: ${payload[0]} ${payload[1]}`);
        if (await predicate(record)) return;
      }
      const { value, done } = await this.read_chunk(reader);
      if (done) throw new Error("TLS receive server is closed");
      this.record_reader.put(value);
    }
  }

  async tls12_encrypt(plaintext, type) {
    const seqbuf = new Uint8Array(8);
    new DataView(seqbuf.buffer).setBigUint64(0, this.client_seq++, false);
    const aad = chunkscat_arr8(seqbuf,
      [ type, 0x03, 0x03 ], uint16bearr8([ plaintext.length ]));
    const nonce = get_random(8);
    return chunkscat_arr8(nonce, await tls12_aesgcm_encrypt(this.crypto_keypair,
      chunkscat_arr8(this.encrypt_iv, nonce), plaintext, aad));
  }

  async tls12_decrypt(ciphertext, type) {
    const seqbuf = new Uint8Array(8);
    new DataView(seqbuf.buffer).setBigUint64(0, this.server_seq++, false);
    const aad = chunkscat_arr8(seqbuf,
      [ type, 0x03, 0x03 ], uint16bearr8([ ciphertext.length - 24 ]));
    const nonce = ciphertext.slice(0, 8);
    return await tls12_aesgcm_decrypt(this.crypto_keypair,
      chunkscat_arr8(this.decrypt_iv, nonce), ciphertext.slice(8), aad);
  }

  async write(data) {
    const plaintext = new Uint8Array(data); if (!plaintext.length) return;
    const writer = this.socket.writable.getWriter();
    try {
      for (let offset = 0; offset < plaintext.length; offset += 16384) {
        const chunk = plaintext.slice(offset, offset + 16384);
        const ciphertext = await this.tls12_encrypt(chunk, 0x17);
        await writer.write(build_client_record(ciphertext, 0x17).record);
      }
    } finally { writer.releaseLock(); }
  }

  async read() {
    while (true) {
      while (true) {
        const record = this.record_reader.get(); if (!record) break;
        const payload = record.payload;
        if (record.type == 0x15) {
          const plaintext = await this.tls12_decrypt(payload, 0x15);
          if (plaintext[0] == 1 && plaintext[1] == 0) {
            console.log("TLS alert is server close");
            return { value: null, done: true };
          } throw new Error(`TLS Alert: ${plaintext[0]} ${plaintext[1]}`);
        }
        if (record.type != 0x17)
          throw new Error(`TLS record is not application data: ${record.type}`);
        return { value: await this.tls12_decrypt(payload, 0x17), done: false };
      }
      const reader = this.socket.readable.getReader();
      try {
        const { value, done } = await this.read_chunk(reader);
        if (done) return { value: null, done: true };
        this.record_reader.put(value);
      } finally { reader.releaseLock(); }
    }
  }

  close() { this.socket.close(); }
}

export class HTTP_Reader { /* http1.1 response reader */
  constructor() {
    this.buffer = new Uint8Array(0);
    this.status_code = null;
    this.reason_phrase = null;
    this.header = new Map();
    this.content_length = 0;
    this.length = 0;
    this.start_status = false;
  }
  start() {
    const x = textdecode(this.buffer);
    const e = x.match(/\r\n\r\n/); if (!e) return false;
    const y = x.slice(0, e?.index);
    const s = y.split("\r\n")[0].match(/^HTTP\/1.1 (\d+) (.*$)/);
    this.status_code = s?.[1]; this.reason_phrase = s?.[2];
    for (const h of y.split("\r\n").slice(1)) {
      const w = h.match(/: /); const k = h.slice(0, w?.index);
      const v = h.slice(w?.index + 2); this.header.set(k, v);
    }
    // {header}\r\n\r\n{hex}\r\n{body}\r\n...0\r\n\r\n => Transfer-Encoding: chunked
    // {header}\r\n\r\nvvvvvvvcccvvvvvvvvvvvvvvvvvvvvv => Content-Length: {size}
    if (this.header.get("Content-Length")) {
      this.content_length = parseInt(this.header.get("Content-Length"));
      if (Number.isNaN(this.content_length)) throw new Error("content length error");
    }
    this.buffer = this.buffer.slice(e?.[0].length + e?.index); return true;
  }
  put(chunk) {
     this.buffer = chunkscat_arr8(this.buffer, new Uint8Array(chunk));
     if (!this.start_status) this.start_status = this.start();
  }
  get() {
    if (!this.start_status) return null;
    const buffer = this.buffer;
    if (this.header.get("Transfer-Encoding") == "chunked") {
      const x = textdecode(buffer.slice(0, 24));
      const e = x.match(/^([0-9A-Fa-f]+)\r\n(\r\n)?/); if (!e) return null;
      const n = parseInt('0x' + e?.[1]);
      if (Number.isNaN(n)) throw new Error("chunked header length error");
      if (!n) {
        this.buffer = buffer.slice(e?.[0].length + 2);
        return { body: new Uint8Array(0), done: true };
      }
      const body = buffer.slice(e?.[0].length, e?.[0].length + n);
      if (body.length != n) return null;
      this.length += body.length;
      this.buffer = buffer.slice(e?.[0].length + n + 2);
      return { body: body, done: false };
    }
    if (this.header.get("Content-Length")) {
      const n = this.content_length - this.length;
      if (!n) return { body: new Uint8Array(0), done: true };
      if (n > buffer.length) {
        if (!buffer.length) return null;
        this.length += buffer.length;
        this.buffer = buffer.slice(buffer.length);
        return { body: buffer, done: false };
      }
      this.length += n;
      this.buffer = buffer.slice(n);
      return { body: buffer.slice(0, n), done: true };
    }
    this.length += buffer.length;
    this.buffer = buffer.slice(buffer.length);
    return { body: buffer, done: true };
  }
  over() { return this.buffer; };
}
