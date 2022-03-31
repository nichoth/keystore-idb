import test from 'tape'
import * as keystore from '../../lib/keystore'
import * as uint8arrays from "uint8arrays"


test('get keypair', async t => {
  const ks = await keystore.init()
  const kp = await ks.getKeypair()

  t.ok(kp.publicKey, 'keypair.publicKey should exist')
  t.ok(kp.sign, 'keypair.sign should exist')

  var sig = await kp.sign(uint8arrays.fromString('my message'))
  t.ok(sig, 'should sign a message')

  t.ok(kp.did().includes('did:key'), 'should return a did')

  var isValid = await ks.verify('my message', uint8arrays.toString(sig),
    kp.publicKeyStr())

  t.equal(isValid, true, 'should create a valid signature')

  t.end()
})
