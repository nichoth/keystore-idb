// var test = require('tape')
import test from 'tape'
import * as keystore from '../lib/keystore/index.js'
import { fromString, /*toString*/ } from 'uint8arrays/from-string'

test('get keypair', async t => {
    var ks
    try {
        ks = await keystore.init()
    } catch(err) {
        console.log('errrrrr', err)
    }

    var kp = await ks.getKeypair()
    console.log('*ks*', ks)
    console.log('**kp in test**', kp)
    // t.ok(kp.did(), 'should have the did function')

    var sig = await kp.sign(fromString('my message'))
    const writeKey = await ks.publicWriteKey()
    var isValid = await ks.verify(fromString('my message'), sig, kp.publicKeyStr())

    t.equal(isValid, true, 'should give a valid signature')
    t.equal(typeof kp.publicKeyStr(), 'string',
        'should return pub key as string')
    t.ok(kp.publicKeyStr() === writeKey, 'keys are equal')

    t.end()
})
