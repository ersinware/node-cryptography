import base64url from "base64url"
import { createHash, createSign, createVerify } from "crypto"
import { readFileSync } from "fs"
import { decryptWithPublicKey, encryptWithPrivateKey, generateKeyPair } from "./util/util.js"

const payload = {
    name: 'Ersin',
    surname: 'Karaer',
    citizenNumber: 'Never put personal information because the signed message does not hide the information'
},
    conf = { algorithm: 'sha256', payload },
    { publicKeyPath, privateKeyPath } = generateKeyPair()

const signed = signMessage()
verifyMessage(signed)

function signMessage(): NonSharedBuffer {
    const hash = createHash(conf.algorithm)
    hash.update(JSON.stringify(payload))

    const signed = encryptWithPrivateKey(readFileSync(privateKeyPath, 'utf-8'), hash.digest('hex'))
    console.log(`SIGNED:\n${signed.toString('hex')}`)

    return signed
}

function verifyMessage(signed: NonSharedBuffer) {
    const hash = createHash(conf.algorithm)
    hash.update(JSON.stringify(conf.payload))

    const decrypted = decryptWithPublicKey(readFileSync(publicKeyPath, 'utf-8'), signed)

    hash.digest('hex') === decrypted.toString() ? console.log('valid') : console.log('invalid');
}

// 

const jwtHeader = {
    'alg': 'RS256',
    'typ': 'JWT'
},
    jwtPayload = {
        'sub': '1234567890',
        'name': 'John Doe',
        'admin': true,
        'iat': 1516239022
    },
    jwtConf = { algorithm: 'RSA-SHA256' }

const jwt = issueToken()
verifyToken(jwt)

function issueToken(): string {
    const headerBase64 = base64url(JSON.stringify(jwtHeader)),
        payloadBase64 = base64url(JSON.stringify(jwtPayload)),
        signer = createSign(jwtConf.algorithm)

    signer.write(`${headerBase64}.${payloadBase64}`)
    signer.end()

    const signatureBase64 = signer.sign(readFileSync(privateKeyPath, 'utf-8'), 'base64url')

    const jwt = headerBase64 + '.' + payloadBase64 + '.' + signatureBase64
    console.log(`\nISSUED TOKEN:\n${jwt}`)

    return jwt
}

function verifyToken(jwt: string) {
    const jwtParts = jwt.split('.'),
        headerInBase64 = jwtParts[0],
        payloadInBase64 = jwtParts[1],
        signatureInBase64 = jwtParts[2],
        verifier = createVerify(jwtConf.algorithm)

    verifier.write(`${headerInBase64}.${payloadInBase64}`)
    verifier.end()

    verifier.verify(readFileSync(publicKeyPath, 'utf-8'), signatureInBase64, 'base64url') ? console.log('valid') : console.log('invalid')
}