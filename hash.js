var sodium = require('sodium-native')
var assert = require('nanoassert')
var hmacSHA256 = require('crypto-js/hmac-sha256')
var dh = require('./dh')

var HASHLEN = 32
var BLOCKLEN = 64

module.exports = {
  HASHLEN,
  BLOCKLEN,
  hash,
  hkdf
}

function hash (out, data) {
  assert(out.byteLength === HASHLEN)
  assert(Array.isArray(data))

  sodium.crypto_generichash_batch(out, data)
}

/**
 * @param {Buffer} out
 * @param {{ toString: () => string | CryptoJS.WordArray; }} key
 * @param {Buffer[] | CryptoJS.LibWordArray} data
 */
function hmac (out, key, data) {
  const res = hmacSHA256(data.toString(), key.toString())
  out.set(Buffer.from(res.toString(), 'hex'))
}

var TempKey = sodium.sodium_malloc(HASHLEN)
var Byte0x01 = Buffer.from([0x01])
var Byte0x02 = Buffer.from([0x02])
var Byte0x03 = Buffer.from([0x03])

function hkdf (out1, out2, out3, chainingKey, inputKeyMaterial) {
  assert(out1.byteLength === HASHLEN)
  assert(out2.byteLength === HASHLEN)
  assert(out3 == null ? true : out3.byteLength === HASHLEN)
  assert(chainingKey.byteLength === HASHLEN)
  assert([0, 32, dh.DHLEN, dh.PKLEN].includes(inputKeyMaterial.byteLength))

  sodium.sodium_memzero(TempKey)
  hmac(TempKey, chainingKey, [inputKeyMaterial])
  hmac(out1, TempKey, [Byte0x01])
  hmac(out2, TempKey, [out1, Byte0x02])

  if (out3 != null) {
    hmac(out3, TempKey, [out2, Byte0x03])
  }

  sodium.sodium_memzero(TempKey)
}
