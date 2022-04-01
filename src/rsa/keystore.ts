import { SupportedEncodings } from "uint8arrays/util/bases"
type Encodings = SupportedEncodings
import IDB from '../idb.js'
import keys from './keys.js'
import operations from './operations.js'
import config from '../config.js'
import utils from '../utils.js'
import KeyStoreBase from '../keystore/base.js'
import { KeyStore, Config, KeyUse, CryptoSystem, Msg, PublicKey,
  PrivateKey, Keypair, KeyType  } from '../types.js'
import * as uint8arrays from "uint8arrays"
import { publicKeyBytesToDid } from "../utils.js"

export class RSAKeyStore extends KeyStoreBase implements KeyStore {

  static async init(maybeCfg?: Partial<Config>): Promise<RSAKeyStore> {
    const cfg = config.normalize({
      ...(maybeCfg || {}),
      type: CryptoSystem.RSA
    })

    const { rsaSize, hashAlg, storeName, exchangeKeyName, writeKeyName } = cfg
    const store = IDB.createStore(storeName)

    await IDB.createIfDoesNotExist(exchangeKeyName, () => (
      keys.makeKeypair(rsaSize, hashAlg, KeyUse.Exchange)
    ), store)
    await IDB.createIfDoesNotExist(writeKeyName, () => (
      keys.makeKeypair(rsaSize, hashAlg, KeyUse.Write)
    ), store)

    return new RSAKeyStore(cfg, store)
  }

  getAlg() {
    return this.cfg.type
  }

  async getKeypair (): Promise<Keypair | null> {
    const publicKey = await this.publicWriteKey()
    const ksAlg = this.getAlg()
    const pubKeyBytes = uint8arrays.fromString(publicKey, "base64pad")
  
    return {
      publicKey: uint8arrays.fromString(publicKey, "base64pad"),
      keyType: keyTypeFromSystem(ksAlg),

      publicKeyStr: function (encoding: Encodings = "base64pad"): string {
        return uint8arrays.toString(pubKeyBytes, encoding)
      },

      did(): string {
        return publicKeyBytesToDid(pubKeyBytes, keyTypeFromSystem(ksAlg))
      },

      sign: async (msg: Uint8Array): Promise<Uint8Array> => {
        const msgString = uint8arrays.toString(msg, "utf8")
        // Sign with the private write key:
        // https://github.com/fission-suite/keystore-idb/blob/c1cf7c42a525500b2874e0715f1ff87997337901/src/rsa/keystore.ts#L31
        const signedString = await this.sign(msgString)
        return uint8arrays.fromString(signedString, "utf8")
      }
    }
  }


  async sign(msg: Msg, cfg?: Partial<Config>): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const writeKey = await this.writeKey()

    return utils.arrBufToBase64(await operations.sign(
      msg,
      writeKey.privateKey as PrivateKey,
      mergedCfg.charSize
    ))
  }

  async verify(
    msg: string,
    sig: string,
    publicKey: string | PublicKey,
    cfg?: Partial<Config>
  ): Promise<boolean> {
    const mergedCfg = config.merge(this.cfg, cfg)

    return operations.verify(
      msg,
      sig,
      publicKey,
      mergedCfg.charSize,
      mergedCfg.hashAlg
    )
  }

  async encrypt(
    msg: Msg,
    publicKey: string | PublicKey,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)

    return utils.arrBufToBase64(await operations.encrypt(
      msg,
      publicKey,
      mergedCfg.charSize,
      mergedCfg.hashAlg
    ))
  }

  async decrypt(
    cipherText: Msg,
    publicKey?: string | PublicKey, // unused param so that keystore interfaces match
    cfg?: Partial<Config>
  ): Promise<string> {
    const exchangeKey = await this.exchangeKey()
    const mergedCfg = config.merge(this.cfg, cfg)

    return utils.arrBufToStr(
      await operations.decrypt(
        cipherText,
        exchangeKey.privateKey as PrivateKey,
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
}

export default RSAKeyStore

function keyTypeFromSystem(system: CryptoSystem, curve?: NamedCurve): KeyType {
  return 'rsa'
}

// z is the multibase prefix for base58btc byte encoding
// const BASE58_DID_PREFIX = "did:key:z"

// function publicKeyBytesToDid(
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
