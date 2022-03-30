import aes from '../aes/index.js'
import idb from '../idb.js'
import utils from '../utils.js'
import config from '../config.js'
import { Config, Keypair, Didable } from '../types.js'
import { checkIsKeyPair } from '../errors.js'
// import * as uint8arrays from "uint8arrays"
import { webcrypto } from "one-webcrypto"
// import ucan from 'ucans'

// import { EdKeypair } from 'ucans'

// import { SupportedEncodings } from "uint8arrays/util/bases"
// type Encodings = SupportedEncodings


export default class KeyStoreBase {

  cfg: Config
  protected store: LocalForage

  constructor(cfg: Config, store: LocalForage) {
    this.cfg = cfg
    this.store = store
  }

  async writeKey(): Promise<CryptoKeyPair> {
    const maybeKey = await idb.getKeypair(this.cfg.writeKeyName, this.store)
    return checkIsKeyPair(maybeKey)
  }

  async exchangeKey(): Promise<CryptoKeyPair> {
    const maybeKey = await idb.getKeypair(this.cfg.exchangeKeyName, this.store)
    return checkIsKeyPair(maybeKey)
  }







  // async getKeypair (): Promise<Keypair | null> {
  //   const publicKey = await this.publicWriteKey()
  //   const ksAlg = await impl.keystore.getAlg()
  
  //   return {
  //     publicKey: uint8arrays.fromString(publicKey, "base64pad"),
  //     keyType: keyTypeFromSystem(ksAlg),
  //     sign: async (msg: Uint8Array): Promise<Uint8Array> => {
  //       const msgString = uint8arrays.toString(msg, "utf8")
  //       // Sign with the private write key:
  //       // https://github.com/fission-suite/keystore-idb/blob/c1cf7c42a525500b2874e0715f1ff87997337901/src/rsa/keystore.ts#L31
  //       const signedString = await impl.keystore.sign(msgString)
  //       return uint8arrays.fromString(signedString, "utf8")
  //     }
  //   }
  // }
   


  // return a UCAN-compatible keypair from this keystore
  // async getKeypair (): Promise<Keypair | null> {
  //   var cfg = this.cfg
  //   var pair = await idb.getKeypair(cfg.writeKeyName, this.store)

  //   if (!pair || !pair.publicKey || !pair.privateKey) return null

  //   // const publicKey = await rsa.exportKey(pair.publicKey)
  //   const publicKey = await exportKey(pair.publicKey)

  //   // this line throws
  //   // const privateKey = await rsa.exportKey(pair.privateKey)

  //   const privateKey = await crypto.subtle.exportKey('jwk', pair.privateKey)

  //   console.log('**pub & priv**', publicKey, privateKey)

  //   if (cfg.type === 'ecc') {
  //     // for type checking 
  //     if (!privateKey.n) return null

  //     // TODO -- what is `privateKey.n`?
  //     var priv = uint8arrays.fromString(privateKey.n)
  //     let kp = new EdKeypair(priv, publicKey, true)
  //     return kp
  //   }

  //   // TODO -- handle RSA keys
  //   return null
  // }









  async getSymmKey(keyName: string, cfg?: Partial<Config>): Promise<CryptoKey> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const maybeKey = await idb.getKey(keyName, this.store)
    if(maybeKey !== null) {
      return maybeKey
    }
    const key = await aes.makeKey(config.symmKeyOpts(mergedCfg))
    await idb.put(keyName, key, this.store)
    return key
  }

  async keyExists(keyName: string): Promise<boolean> {
    const key = await idb.getKey(keyName, this.store)
    return key !== null
  }

  async deleteKey(keyName: string): Promise<void> {
    return idb.rm(keyName, this.store)
  }

  async destroy(): Promise<void> {
    return idb.dropStore(this.store)
  }

  async importSymmKey(keyStr: string, keyName: string, cfg?: Partial<Config>): Promise<void> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const key = await aes.importKey(keyStr, config.symmKeyOpts(mergedCfg))
    await idb.put(keyName, key, this.store)
  }

  async exportSymmKey(keyName: string, cfg?: Partial<Config>): Promise<string> {
    const key = await this.getSymmKey(keyName, cfg)
    return aes.exportKey(key)
  }

  async encryptWithSymmKey(msg: string, keyName: string, cfg?: Partial<Config>): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const key = await this.getSymmKey(keyName, cfg)
    const cipherText = await aes.encryptBytes(
      utils.strToArrBuf(msg, mergedCfg.charSize),
      key,
      config.symmKeyOpts(mergedCfg)
    )
    return utils.arrBufToBase64(cipherText)
  }

  async decryptWithSymmKey(cipherText: string, keyName: string, cfg?: Partial<Config>): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const key = await this.getSymmKey(keyName, cfg)
    const msgBytes = await aes.decryptBytes(
      utils.base64ToArrBuf(cipherText),
      key,
      config.symmKeyOpts(mergedCfg)
    )
    return utils.arrBufToStr(msgBytes, mergedCfg.charSize)
  }
}

const exportKey = async (key: CryptoKey): Promise<Uint8Array> => {
  const buf = await webcrypto.subtle.exportKey("spki", key)
  return new Uint8Array(buf)
}

// class EdKeypair implements Keypair, Didable {
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
// }
