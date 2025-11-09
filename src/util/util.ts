import {
    generateKeyPairSync,
    KeyPairSyncResult,
    privateEncrypt,
    publicDecrypt
} from 'crypto'
import { writeFileSync } from 'fs'
import { join } from 'path'

export function generateKeyPair(): { publicKeyPath: string, privateKeyPath: string } {
    const keyPair: KeyPairSyncResult<string, string> =
        generateKeyPairSync(
            'rsa',
            {
                modulusLength: 4096,
                publicKeyEncoding: {
                    type: 'pkcs1',
                    format: 'pem'
                },
                privateKeyEncoding: {
                    type: 'pkcs1',
                    format: 'pem'
                },
            }
        ),
        root = process.cwd(),
        keysDir = join(root, 'keys'),
        publicKeyPath = join(keysDir, 'public-key.pem'),
        privateKeyPath = join(keysDir, 'private-key.pem')

    writeFileSync(publicKeyPath, keyPair.publicKey)
    writeFileSync(privateKeyPath, keyPair.privateKey)

    console.log(`successfully generated and saved keys to: ${keysDir}`)

    return {
        publicKeyPath,
        privateKeyPath
    }
}

export function encryptWithPrivateKey(privateKey: string, message: string) {
    return privateEncrypt(privateKey, Buffer.from(message, 'utf-8'))
}

export function decryptWithPublicKey(publicKey: string, encryptedMessage: NonSharedBuffer) {
    return publicDecrypt(publicKey, encryptedMessage)
}