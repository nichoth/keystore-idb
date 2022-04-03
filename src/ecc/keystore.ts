import { SupportedEncodings } from "uint8arrays/util/bases"
type Encodings = SupportedEncodings
import IDB from '../idb.js'
import keys from './keys.js'
import operations from './operations.js'
import config from '../config.js'
import utils from '../utils.js'
import KeyStoreBase from '../keystore/base.js'
import { Keypair, KeyStore, Config, KeyUse, CryptoSystem,
  PrivateKey, /*KeyType*/ } from '../types.js'
import * as uint8arrays from "uint8arrays"
// import { publicKeyBytesToDid } from "../utils.js"
// import ucan from 'ucans'
import * as ucan from 'ucans'


export class ECCKeyStore extends KeyStoreBase implements KeyStore {

  static async init(maybeCfg?: Partial<Config>): Promise<ECCKeyStore> {
    const cfg = config.normalize({
      ...(maybeCfg || {}),
      type: CryptoSystem.ECC
    })
    const { curve, storeName, exchangeKeyName, writeKeyName } = cfg

    const store = IDB.createStore(storeName)
    await IDB.createIfDoesNotExist(exchangeKeyName, () => (
      keys.makeKeypair(curve, KeyUse.Exchange)
    ), store)
    await IDB.createIfDoesNotExist(writeKeyName, () => (
      keys.makeKeypair(curve, KeyUse.Write)
    ), store)

    return new ECCKeyStore(cfg, store)
  }


  async sign(msg: string, cfg?: Partial<Config>): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const writeKey = await this.writeKey()

    return utils.arrBufToBase64(await operations.sign(
      msg,
      writeKey.privateKey as PrivateKey,
      mergedCfg.charSize,
      mergedCfg.hashAlg
    ))
  }

  async verify(
    msg: string,
    sig: string,
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<boolean> {
    const mergedCfg = config.merge(this.cfg, cfg)

    return operations.verify(
      msg,
      sig,
      publicKey,
      mergedCfg.charSize,
      mergedCfg.curve,
      mergedCfg.hashAlg
    )
  }

  async encrypt(
    msg: string,
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const exchangeKey = await this.exchangeKey()

    return utils.arrBufToBase64(await operations.encrypt(
      msg,
      exchangeKey.privateKey as PrivateKey,
      publicKey,
      mergedCfg.charSize,
      mergedCfg.curve
    ))
  }

  async decrypt(
    cipherText: string,
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const exchangeKey = await this.exchangeKey()

    return utils.arrBufToStr(
      await operations.decrypt(
        cipherText,
        exchangeKey.privateKey as PrivateKey,
        publicKey,
        mergedCfg.curve
      ),
      mergedCfg.charSize
    )
  }

  async publicExchangeKey(): Promise<string> {
    const exchangeKey = await this.exchangeKey()
    return operations.getPublicKey(exchangeKey)
  }

  async publicWriteKey(): Promise<string> {
    const writeKey = await this.writeKey()
    return operations.getPublicKey(writeKey)
  }

  getAlg() {
    return this.cfg.type
  }

  async getKeypair (): Promise<Keypair | null> {
    const publicKey = await this.publicWriteKey()
    // const ksAlg = this.getAlg()
    const pubKeyBytes = uint8arrays.fromString(publicKey, 'base64pad')
  
    return {
      // publicKey: uint8arrays.fromString(publicKey, 'base64pad'),
      publicKey: pubKeyBytes,
      keyType: 'ed25519', //keyTypeFromSystem(ksAlg),

      publicKeyStr: function (/*encoding: Encodings = 'base64pad'*/): string {
        return publicKey
        // return uint8arrays.toString(pubKeyBytes, 'base64pad')
      },

      did(): string {
        // return publicKeyBytesToDid(pubKeyBytes, keyTypeFromSystem(ksAlg))
        // console.log('ccccccccccccccccccccc', pubKeyBytes)
        // return publicKeyBytesToDid(pubKeyBytes, 'ed25519')
        return ucan.publicKeyBytesToDid(pubKeyBytes, 'ed25519')
      },

      sign: async (msg: Uint8Array): Promise<Uint8Array> => {
        const msgString = uint8arrays.toString(msg, 'utf8')
        // Sign with the private write key:
        // https://github.com/fission-suite/keystore-idb/blob/c1cf7c42a525500b2874e0715f1ff87997337901/src/rsa/keystore.ts#L31
        const signedString = await this.sign(msgString)
        return uint8arrays.fromString(signedString, 'utf8')
      }
    }
  }

}

export default ECCKeyStore

// const BASE58_DID_PREFIX = "did:key:z" // z is the multibase prefix for base58btc byte encoding

/**
 * Convert a public key in bytes to a DID (did:key).
 */
//  export function publicKeyBytesToDid(
//   publicKeyBytes: Uint8Array,
//   type: KeyType,
// ): string {
//   // Prefix public-write key
//   const prefix = magicBytes(type)
//   if (prefix === null) {
//     throw new Error(`Key type '${type}' not supported`)
//   }

//   const prefixedBytes = uint8arrays.concat([prefix, publicKeyBytes])

//   // Encode prefixed
//   return BASE58_DID_PREFIX + uint8arrays.toString(prefixedBytes, "base58btc")
// }




// export default abstract class BaseKeypair implements Keypair, Didable, ExportableKey {

//   publicKey: Uint8Array
//   keyType: KeyType
//   exportable: boolean

//   constructor(publicKey: Uint8Array, keyType: KeyType, exportable: boolean) {
//     this.publicKey = publicKey
//     this.keyType = keyType
//     this.exportable = exportable
//   }

//   publicKeyStr(encoding: Encodings = "base64pad"): string {
//     return uint8arrays.toString(this.publicKey, encoding)
//   }

//   did(): string {
//     return publicKeyBytesToDid(this.publicKey, this.keyType)
//   }

//   abstract sign(msg: Uint8Array): Promise<Uint8Array>
//   abstract export(): Promise<string>
// }






// /**
//  * Translate a `CryptoSystem` from the keystore-idb library
//  * to a `KeyType` from the ucans library.
//  *
//  * @param system The `CryptoSystem` we want to translate
//  */
// function keyTypeFromSystem(system: CryptoSystem, curve?: NamedCurve): KeyType {
//   return 'p256'
//   // switch (system) {
//   //   case "ecc":
//   //     switch (curve) {
//   //       // TODO: Next ucans release
//   //       // case "P-256":
//   //       //   return "p256"
//   //       // case "P-384":
//   //       //   return "p384"
//   //       // case "P-521":
//   //       //   return "p521"
//   //       default:
//   //         if (!curve) throw new Error("Missing `curve` parameter (necessary for `ecc`)")
//   //         throw new Error("Invalid `curve` (not supported by keystore-idb)")
//   //     }

//   //   // case "rsa":
//   //   //   return "rsa"

//   //   default:
//   //     throw new Error("Invalid `CryptoSystem`")
//   // }
// }


// // /** https://github.com/multiformats/multicodec/blob/e9ecf587558964715054a0afcc01f7ace220952c/table.csv#L94 */
// // const EDWARDS_DID_PREFIX = new Uint8Array([0xed, 0x01])
// // /** https://github.com/multiformats/multicodec/blob/e9ecf587558964715054a0afcc01f7ace220952c/table.csv#L91 */
// // const BLS_DID_PREFIX = new Uint8Array([0xea, 0x01])
// // /** https://github.com/multiformats/multicodec/blob/e9ecf587558964715054a0afcc01f7ace220952c/table.csv#L141 */
// // const P256_DID_PREFIX = new Uint8Array([0x80, 0x24])
// // /** https://github.com/multiformats/multicodec/blob/e9ecf587558964715054a0afcc01f7ace220952c/table.csv#L142 */
// // const P384_DID_PREFIX = new Uint8Array([0x81, 0x24])
// // /** https://github.com/multiformats/multicodec/blob/e9ecf587558964715054a0afcc01f7ace220952c/table.csv#L143 */
// // const P521_DID_PREFIX = new Uint8Array([0x82, 0x24])
// // /** https://github.com/multiformats/multicodec/blob/e9ecf587558964715054a0afcc01f7ace220952c/table.csv#L146 */
// // const RSA_DID_PREFIX = new Uint8Array([0x85, 0x24])
// // /** Old RSA DID prefix, used pre-standardisation */
// // const RSA_DID_PREFIX_OLD = new Uint8Array([0x00, 0xf5, 0x02])

// // function magicBytes(keyType: KeyType): Uint8Array | null {
// //   switch (keyType) {
// //     case "ed25519":
// //       return EDWARDS_DID_PREFIX
// //     case "p256":
// //       return P256_DID_PREFIX
// //     case "p384":
// //       return P384_DID_PREFIX
// //     case "p521":
// //       return P521_DID_PREFIX
// //     case "rsa":
// //       return RSA_DID_PREFIX
// //     case "bls12-381":
// //       return BLS_DID_PREFIX
// //     default:
// //       return null
// //   }
// // }