import loadOqs from './liboqs.mjs';

export const KEMS = {
  'ML-KEM-768': { public: 1184, secret: 2400, cipher: 1088, level: 3, experimental: false },
  'HQC-3': { public: 4514, secret: 4602, cipher: 8978, level: 3, experimental: true },
};

const signature = { public: 1952, secret: 4032, bytes: 3309 };
const utf8 = new TextEncoder();
const subtle = globalThis.crypto.subtle;
let modulePromise;

export function random(size) {
  return crypto.getRandomValues(new Uint8Array(size));
}

export const encode = bytes => btoa(String.fromCharCode(...bytes));

export function decode(text, size) {
  if (typeof text !== 'string' || text.length !== Math.ceil(size / 3) * 4) {
    throw new Error('Unexpected cryptographic input size');
  }
  const bytes = Uint8Array.from(atob(text), character => character.charCodeAt(0));
  if (bytes.length !== size || encode(bytes) !== text) throw new Error('Invalid base64 encoding');
  return bytes;
}

export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
}

export const bytes = text => utf8.encode(text);
export const hash = async data => new Uint8Array(await subtle.digest('SHA-256', data));

export async function derive(secret, label, salt = new Uint8Array(32)) {
  const key = await subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({
    name: 'HKDF', hash: 'SHA-256', salt, info: bytes('crytosage/browser/1/' + label),
  }, key, 256));
}

export async function authenticate(secret, value, proof) {
  const key = await subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  const data = bytes(canonical(value));
  if (proof === undefined) return encode(new Uint8Array(await subtle.sign('HMAC', key, data)));
  return subtle.verify('HMAC', key, decode(proof, 32), data);
}

export async function crypt(operation, secret, counter, header, payload) {
  const key = await subtle.importKey('raw', secret, 'AES-GCM', false, [operation]);
  const iv = new Uint8Array(12);
  new DataView(iv.buffer).setUint32(8, counter);
  return new Uint8Array(await subtle[operation]({ name: 'AES-GCM', iv, additionalData: bytes(canonical(header)) }, key, payload));
}

export async function getOqs() {
  const oqs = await (modulePromise ??= loadOqs());
  function call(type, name, action) {
    const allocations = [];
    function buffer(data) {
      const size = typeof data === 'number' ? data : data.length;
      const pointer = oqs._malloc(size);
      if (!pointer) throw new Error('Cryptographic memory allocation failed');
      allocations.push([pointer, size]);
      if (typeof data !== 'number') oqs.HEAPU8.set(data, pointer);
      return pointer;
    }
    const take = (pointer, size) => oqs.HEAPU8.slice(pointer, pointer + size);
    let handle;
    try {
      handle = oqs['_OQS_' + type + '_new'](buffer(bytes(name + '\0')));
      if (!handle) throw new Error('The required liboqs implementation is unavailable');
      return action(handle, buffer, take);
    } finally {
      if (handle) oqs['_OQS_' + type + '_free'](handle);
      for (const [pointer, size] of allocations) {
        oqs.HEAPU8.fill(0, pointer, pointer + size);
        oqs._free(pointer);
      }
    }
  }
  function requireSuccess(code) {
    if (code !== 0) throw new Error('liboqs rejected the operation');
  }
  function keypair(type, name, sizes) {
    return call(type, name, (handle, buffer, take) => {
      const publicKey = buffer(sizes.public), secret = buffer(sizes.secret);
      requireSuccess(oqs['_OQS_' + type + '_keypair'](handle, publicKey, secret));
      return { public: encode(take(publicKey, sizes.public)), secret: take(secret, sizes.secret) };
    });
  }
  return {
    identity: () => keypair('SIG', 'ML-DSA-65', signature),
    keypair: name => keypair('KEM', name, KEMS[name]),
    sign: (secret, data) => call('SIG', 'ML-DSA-65', (handle, buffer, take) => {
      const output = buffer(signature.bytes), length = buffer(4);
      requireSuccess(oqs._OQS_SIG_sign(handle, output, length, buffer(data), data.length, buffer(secret)));
      if (oqs.HEAPU32[length >>> 2] !== signature.bytes) throw new Error('Unexpected signature size');
      return encode(take(output, signature.bytes));
    }),
    verify: (publicKey, data, signed) => call('SIG', 'ML-DSA-65', (handle, buffer) =>
      oqs._OQS_SIG_verify(handle, buffer(data), data.length, buffer(decode(signed, signature.bytes)),
        signature.bytes, buffer(decode(publicKey, signature.public))) === 0),
    encapsulate: (name, publicKey) => call('KEM', name, (handle, buffer, take) => {
      const sizes = KEMS[name], ciphertext = buffer(sizes.cipher), secret = buffer(32);
      requireSuccess(oqs._OQS_KEM_encaps(handle, ciphertext, secret, buffer(decode(publicKey, sizes.public))));
      return { ciphertext: encode(take(ciphertext, sizes.cipher)), secret: take(secret, 32) };
    }),
    decapsulate: (name, secret, ciphertext) => call('KEM', name, (handle, buffer, take) => {
      const shared = buffer(32);
      requireSuccess(oqs._OQS_KEM_decaps(handle, shared, buffer(decode(ciphertext, KEMS[name].cipher)), buffer(secret)));
      return take(shared, 32);
    }),
  };
}
