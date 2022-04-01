import { webcrypto } from 'one-webcrypto'
import * as uint8arrays from 'uint8arrays'
import errors from './errors.js'
import { CharSize, Msg } from './types.js'
import { KeyType } from './types.js'

/** https://github.com/multiformats/multicodec/blob/e9ecf587558964715054a0afcc01f7ace220952c/table.csv#L94 */
const EDWARDS_DID_PREFIX = new Uint8Array([0xed, 0x01])
/** https://github.com/multiformats/multicodec/blob/e9ecf587558964715054a0afcc01f7ace220952c/table.csv#L91 */
const BLS_DID_PREFIX = new Uint8Array([0xea, 0x01])
/** https://github.com/multiformats/multicodec/blob/e9ecf587558964715054a0afcc01f7ace220952c/table.csv#L141 */
const P256_DID_PREFIX = new Uint8Array([0x80, 0x24])
/** https://github.com/multiformats/multicodec/blob/e9ecf587558964715054a0afcc01f7ace220952c/table.csv#L142 */
const P384_DID_PREFIX = new Uint8Array([0x81, 0x24])
/** https://github.com/multiformats/multicodec/blob/e9ecf587558964715054a0afcc01f7ace220952c/table.csv#L143 */
const P521_DID_PREFIX = new Uint8Array([0x82, 0x24])
/** https://github.com/multiformats/multicodec/blob/e9ecf587558964715054a0afcc01f7ace220952c/table.csv#L146 */
const RSA_DID_PREFIX = new Uint8Array([0x85, 0x24])
/** Old RSA DID prefix, used pre-standardisation */
// const RSA_DID_PREFIX_OLD = new Uint8Array([0x00, 0xf5, 0x02])


const BASE58_DID_PREFIX = "did:key:z"

/**
 * Convert a public key in bytes to a DID (did:key).
 */
export function publicKeyBytesToDid(
  publicKeyBytes: Uint8Array,
  type: KeyType,
): string {
  // Prefix public-write key
  const prefix = magicBytes(type)
  if (prefix === null) {
    throw new Error(`Key type '${type}' not supported`)
  }

  const prefixedBytes = uint8arrays.concat([prefix, publicKeyBytes])

  // Encode prefixed
  return BASE58_DID_PREFIX + uint8arrays.toString(prefixedBytes, "base58btc")
}



export function magicBytes(keyType: KeyType): Uint8Array | null {
  switch (keyType) {
    case "ed25519":
      return EDWARDS_DID_PREFIX
    case "p256":
      return P256_DID_PREFIX
    case "p384":
      return P384_DID_PREFIX
    case "p521":
      return P521_DID_PREFIX
    case "rsa":
      return RSA_DID_PREFIX
    case "bls12-381":
      return BLS_DID_PREFIX
    default:
      return null
  }
}


export function arrBufToStr(buf: ArrayBuffer, charSize: CharSize): string {
  const arr = charSize === 8 ? new Uint8Array(buf) : new Uint16Array(buf)
  return Array.from(arr)
    .map(b => String.fromCharCode(b))
    .join('')
}

export function arrBufToBase64(buf: ArrayBuffer): string {
  return uint8arrays.toString(new Uint8Array(buf), "base64pad")
}

export function strToArrBuf(str: string, charSize: CharSize): ArrayBuffer {
  const view =
    charSize === 8 ? new Uint8Array(str.length) : new Uint16Array(str.length)
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    view[i] = str.charCodeAt(i)
  }
  return view.buffer
}

export function base64ToArrBuf(string: string): ArrayBuffer {
  return uint8arrays.fromString(string, "base64pad").buffer
}

export function publicExponent(): Uint8Array {
  return new Uint8Array([0x01, 0x00, 0x01])
}

export function randomBuf(length: number, { max }: { max: number } = { max: 255 }): ArrayBuffer {
  if (max < 1 || max > 255) {
    throw errors.InvalidMaxValue
  }

  const arr = new Uint8Array(length)

  if (max == 255) {
    webcrypto.getRandomValues(arr)
    return arr.buffer
  }

  let index = 0
  const interval = max + 1
  const divisibleMax = Math.floor(256 / interval) * interval
  const tmp = new Uint8Array(1)

  while (index < arr.length) {
    webcrypto.getRandomValues(tmp)
    if (tmp[0] < divisibleMax) {
      arr[index] = tmp[0] % interval
      index++
    }
  }

  return arr.buffer
}

export function joinBufs(fst: ArrayBuffer, snd: ArrayBuffer): ArrayBuffer {
  const view1 = new Uint8Array(fst)
  const view2 = new Uint8Array(snd)
  const joined = new Uint8Array(view1.length + view2.length)
  joined.set(view1)
  joined.set(view2, view1.length)
  return joined.buffer
}

export const normalizeUtf8ToBuf = (msg: Msg): ArrayBuffer => {
  return normalizeToBuf(msg, (str) => strToArrBuf(str, CharSize.B8))
}

export const normalizeUtf16ToBuf = (msg: Msg): ArrayBuffer => {
  return normalizeToBuf(msg, (str) => strToArrBuf(str, CharSize.B16))
}

export const normalizeBase64ToBuf = (msg: Msg): ArrayBuffer => {
  return normalizeToBuf(msg, base64ToArrBuf)
}

export const normalizeUnicodeToBuf = (msg: Msg, charSize: CharSize) => {
  switch (charSize) {
    case 8: return normalizeUtf8ToBuf(msg)
    default: return normalizeUtf16ToBuf(msg)
  }
}

export const normalizeToBuf = (msg: Msg, strConv: (str: string) => ArrayBuffer): ArrayBuffer => {
  if (typeof msg === 'string') {
    return strConv(msg)
  } else if (typeof msg === 'object' && msg.byteLength !== undefined) {
    // this is the best runtime check I could find for ArrayBuffer/Uint8Array
    const temp = new Uint8Array(msg)
    return temp.buffer
  } else {
    throw new Error("Improper value. Must be a string, ArrayBuffer, Uint8Array")
  }
}

/* istanbul ignore next */
export async function structuralClone(obj: any) {
  return new Promise(resolve => {
    const { port1, port2 } = new MessageChannel()
    port2.onmessage = ev => resolve(ev.data)
    port1.postMessage(obj)
  })
}

export default {
  arrBufToStr,
  arrBufToBase64,
  strToArrBuf,
  base64ToArrBuf,
  publicExponent,
  randomBuf,
  joinBufs,
  normalizeUtf8ToBuf,
  normalizeUtf16ToBuf,
  normalizeBase64ToBuf,
  normalizeToBuf,
  structuralClone
}
