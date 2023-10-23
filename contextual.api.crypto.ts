import { Bip32PrivateKey, Bip32PublicKey, Ed25519PrivateKey, SodiumBip32Ed25519 } from '@cardano-sdk/crypto'
import {
    crypto_core_ed25519_scalar_add,
    crypto_core_ed25519_scalar_mul,
    crypto_core_ed25519_scalar_reduce,
    crypto_hash_sha512,
    crypto_scalarmult_ed25519_base_noclamp,
    crypto_sign_verify_detached,
    ready,
    crypto_sign_ed25519_pk_to_curve25519,
    crypto_scalarmult
  } from 'libsodium-wrappers-sumo';

/**
 * 
 */
export enum KeyContext {
    Address = 0,
    Identity = 1,
    Cardano = 2,
    TESTVECTOR_1 = 3,
    TESTVECTOR_2 = 4,
    TESTVECTOR_3 = 5
}

export interface ChannelKeys {
    tx: Uint8Array
    rx: Uint8Array
}

export const harden = (num: number): number => 0x80_00_00_00 + num;

function GetBIP44PathFromContext(context: KeyContext, account:number, key_index: number): number[] {
    switch (context) {
        case KeyContext.Address:
            return [harden(44), harden(283), harden(account), 0, key_index]
        case KeyContext.Identity:
            return [harden(44), harden(0), harden(account), 0, key_index]
        default:
            throw new Error("Invalid context")
    }
}

export class ContextualCryptoApi extends SodiumBip32Ed25519 {

    // Only for testing, seed shouldn't be persisted 
    constructor(private readonly entropy: Buffer) {
        super()
    }


    /**
     * 
     * 
     * @param context 
     * @param keyIndex 
     * @returns - public key 32 bytes
     */
    async keyGen(context: KeyContext, account:number, keyIndex: number): Promise<Uint8Array> {
        await ready

        const rootKey: Bip32PrivateKey = await Bip32PrivateKey.fromBip39Entropy(this.entropy, '')
        const bip44Path: number[] = GetBIP44PathFromContext(context, account, keyIndex)
        const childKey: Bip32PrivateKey = await rootKey.derive(bip44Path)
        const pub: Bip32PublicKey = await childKey.toPublic()

        // return 32 bytes
        return new Uint8Array(pub.bytes().slice(0, 32))
    }

    /**
     * Ref: https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.6
     * 
     *  Edwards-Curve Digital Signature Algorithm (EdDSA)
     * */ 
    async signData(context: KeyContext, account: number, keyIndex: number, message: Uint8Array): Promise<Uint8Array> {
        await ready
        const rootKey: Bip32PrivateKey = await Bip32PrivateKey.fromBip39Entropy(this.entropy, '')
        const bip44Path: number[] = GetBIP44PathFromContext(context, account, keyIndex)
        const childKey: Bip32PrivateKey = await rootKey.derive(bip44Path)

        const raw: Ed25519PrivateKey = childKey.toRawKey()

        const scalar = raw.bytes().slice(0, 32);
        const c = raw.bytes().slice(32, 64);

        // \(1): pubKey = scalar * G (base point, no clamp)
        const publicKey = crypto_scalarmult_ed25519_base_noclamp(scalar);

        // \(2): h = hash(c + msg) mod q
        const hash: bigint = Buffer.from(crypto_hash_sha512(Buffer.concat([c, message]))).readBigInt64LE()
        
        // \(3):  r = hash(hash(privKey) + msg) mod q 
        const q: bigint = BigInt(2n ** 252n + 27742317777372353535851937790883648493n);
        const rBigInt = hash % q
        const rBString = rBigInt.toString(16) // convert to hex string

        // fill 32 bytes of r
        // convert to Uint8Array
        const r = new Uint8Array(32) 
        for (let i = 0; i < rBString.length; i += 2) {
            r[i / 2] = parseInt(rBString.substring(i, i + 2), 16);
        }

        // \(4):  R = r * G (base point, no clamp)
        const R = crypto_scalarmult_ed25519_base_noclamp(r)

        let h = crypto_hash_sha512(Buffer.concat([R, publicKey, message]));
        h = crypto_core_ed25519_scalar_reduce(h);

        // \(5): S = (r + h * k) mod q
        const S = crypto_core_ed25519_scalar_add(r, crypto_core_ed25519_scalar_mul(h, scalar))

        return Buffer.concat([R, S]);
    }

    /**
     * 
     * @param publicKey 
     * @param message 
     * @param signature 
     * @returns 
     */
    async verifyWithPublicKey(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
        return crypto_sign_verify_detached(signature, message, publicKey)
    }

    /**
     * 
     * @param context 
     * @param keyIndex 
     * @param otherPartyPub 
     */
    async ECDH(context: KeyContext, account: number, keyIndex: number, otherPartyPub: Uint8Array): Promise<Uint8Array> {
        await ready

        const rootKey: Bip32PrivateKey = await Bip32PrivateKey.fromBip39Entropy(this.entropy, '')
        const bip44Path: number[] = GetBIP44PathFromContext(context, account, keyIndex)
        const childKey: Bip32PrivateKey = await rootKey.derive(bip44Path)

        const pvtKey: Uint8Array = childKey.toRawKey().bytes()
        const scalar: Uint8Array = pvtKey.slice(0, 32)

        return crypto_scalarmult(scalar, crypto_sign_ed25519_pk_to_curve25519(otherPartyPub))
    }
}