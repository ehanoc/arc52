import { createHash, createHmac } from 'crypto';
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

const bip32ed25519 = require("bip32-ed25519");


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
            return [0x8000002c, harden(283), harden(account), 0, key_index]
        case KeyContext.Identity:
            return [harden(44), harden(0), harden(account), 0, key_index]
        default:
            throw new Error("Invalid context")
    }
}

export class ContextualCryptoApi {

    // Only for testing, seed shouldn't be persisted 
    constructor(private readonly seed: Buffer) {

    }

    /**
     * 
     * @param context 
     * @returns 
     */
    private async rootKey(seed: Buffer): Promise<Uint8Array> {
        // SLIP-0010
        // We should have been using [BIP32-Ed25519 HierarchicalDeterministicKeysoveraNon-linear Keyspace] instead
        // Should have been SHA512(seed)
        const c: Buffer = createHmac('sha256', "ed25519 seed").update(Buffer.concat([new Uint8Array([0x1]), seed])).digest()
        let I: Buffer = createHmac('sha512', "ed25519 seed").update(seed).digest()

        // split into KL and KR.
        // (KL, KR) is the extended private key
        let kL = I.subarray(0, 32) 
        let kR = I.subarray(32, 64)

        // SLIP-0010 specific
        // SHOULDN"T BE DONE FOR Ed25519 !
        // but our ledger implementation does it
        while ((kL[31] & 0b00100000) != 0) {
            I = createHmac('sha512', "ed25519 seed").update(I).digest()
            kL = I.subarray(0, 32)
            kR = I.subarray(32, 64)
        }

        // clamping
        // This bit is "compliant" with [BIP32-Ed25519 HierarchicalDeterministicKeysoveraNon-linear Keyspace]
        kL[0] &= 0b11_11_10_00;
        kL[31] &= 0b01_11_11_11;
        kL[31] |= 0b01_00_00_00;

        return new Uint8Array(Buffer.concat([kL, kR, c]))
    }

    /**
     * 
     * @param rootKey 
     * @param account 
     * @param keyIndex 
     * @param isPrivate 
     * @returns 
     */
    private async deriveKey(rootKey: Uint8Array, bip44Path: number[], isPrivate: boolean = true): Promise<Uint8Array> {
        let derived = bip32ed25519.derivePrivate(Buffer.from(rootKey), bip44Path[0])
            derived = bip32ed25519.derivePrivate(derived, bip44Path[1])
            derived = bip32ed25519.derivePrivate(derived, bip44Path[2])
            derived = bip32ed25519.derivePrivate(derived, bip44Path[3])
            derived = bip32ed25519.derivePrivate(derived, bip44Path[4])

            const derivedKl = derived.subarray(0, 32)
            const xpvt = createHash('sha512').update(derivedKl).digest()
            xpvt[0] &= 0b11_11_10_00;
            xpvt[31] &= 0b01_11_11_11;
            xpvt[31] |= 0b01_00_00_00;


        const scalar: Uint8Array = xpvt.subarray(0, 32)
        return isPrivate ? xpvt : crypto_scalarmult_ed25519_base_noclamp(scalar)
    }

    /**
     * 
     * 
     * @param context 
     * @param keyIndex 
     * @returns - public key 32 bytes
     */
    async keyGen(context: KeyContext, account:number, keyIndex: number): Promise<Uint8Array> {
        await ready // libsodium

        const rootKey: Uint8Array = await this.rootKey(this.seed)
        const bip44Path: number[] = GetBIP44PathFromContext(context, account, keyIndex)

        return await this.deriveKey(rootKey, bip44Path, false)
    }

    /**
     * Ref: https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.6
     * 
     *  Edwards-Curve Digital Signature Algorithm (EdDSA)
     * */ 
    async signData(context: KeyContext, account: number, keyIndex: number, message: Uint8Array): Promise<Uint8Array> {
        await ready // libsodium

        const rootKey: Uint8Array = await this.rootKey(this.seed)
        const bip44Path: number[] = GetBIP44PathFromContext(context, account, keyIndex)
        const raw: Uint8Array = await this.deriveKey(rootKey, bip44Path, true)

        const scalar = raw.slice(0, 32);
        const c = raw.slice(32, 64);

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

        const rootKey: Uint8Array = await this.rootKey(this.seed)
        
        const bip44Path: number[] = GetBIP44PathFromContext(context, account, keyIndex)
        const childKey: Uint8Array = await this.deriveKey(rootKey, bip44Path, true)

        const scalar: Uint8Array = childKey.slice(0, 32)

        return crypto_scalarmult(scalar, crypto_sign_ed25519_pk_to_curve25519(otherPartyPub))
    }
}