import { CryptoKX, KeyPair, crypto_box_seal, crypto_kx_client_session_keys, crypto_kx_server_session_keys, crypto_scalarmult, crypto_scalarmult_ed25519_base_noclamp, crypto_secretbox_NONCEBYTES, crypto_secretbox_easy, crypto_secretbox_open_easy, crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519, crypto_sign_keypair, crypto_sign_seed_keypair, ready } from "libsodium-wrappers-sumo"
import * as bip39 from "bip39"
import { read } from "fs"
import { Bip32PrivateKey, Bip32PublicKey } from "@cardano-sdk/crypto"
import { createHmac, randomBytes } from "crypto"
import util from "util"
import { ContextualCryptoApi, KeyContext } from "./contextual.api.crypto"

describe("Contextual Derivation & Signing", () => {

    let cryptoService: ContextualCryptoApi
    let bip39Mnemonic: string = "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice"
    let seed: Buffer

    beforeAll(() => {
        seed = Buffer.from(bip39.mnemonicToEntropy(bip39Mnemonic), "hex")
    })
    
	beforeEach(() => {
        cryptoService = new ContextualCryptoApi(seed)
    })

	afterEach(() => {})

    describe("\(Derivations) Context", () => {
            describe("Addresses", () => {
                describe("Soft Derivations", () => {
                    it("\(OK) Derive m'/44'/283'/0'/0/0 Algorand Address Key", async () => {
                        const key: Uint8Array = await cryptoService.keyGen(KeyContext.Address, 0, 0)
                        expect(key).toEqual(new Uint8Array(Buffer.from("827731008c213af931486dc7144db484a4523586b4ababe72c0766d4b2be2270", "hex")))
                    })
            
                    it("\(OK) Derive m'/44'/283'/0'/0/1 Algorand Address Key", async () => {
                        const key: Uint8Array = await cryptoService.keyGen(KeyContext.Address, 0, 1)
                        expect(key).toEqual(new Uint8Array(Buffer.from("7456093cca8c8e520e748cee627cb1e578153a4dd4de1acc7ecfeec29a97286c", "hex")))
                    })
            
                    it("\(OK) Derive m'/44'/283'/0'/0/2 Algorand Address Key", async () => {
                        const key: Uint8Array = await cryptoService.keyGen(KeyContext.Address, 0, 2)
                        expect(key).toEqual(new Uint8Array(Buffer.from("700023643725c747b848300870eb2086a4bc30b41f1e82692e22c6c48418478e", "hex")))
                    })
                })

                describe("Hard Derivations", () => {
                    it("\(OK) Derive m'/44'/283'/1'/0/0 Algorand Address Key", async () => {
                        const key: Uint8Array = await cryptoService.keyGen(KeyContext.Address, 1, 0)
                        expect(key).toEqual(new Uint8Array(Buffer.from("42a3d8d81cc375e011178af82a7c341955777fac77a6d85420d9727a902a4683", "hex")))
                    })
        
                    it("\(OK) Derive m'/44'/283'/2'/0/1 Algorand Address Key", async () => {
                        const key: Uint8Array = await cryptoService.keyGen(KeyContext.Address, 2, 1)
                        expect(key).toEqual(new Uint8Array(Buffer.from("ea16e84ac5056ce346d969d1e0a3d721a287254511fa3febedd8bc13c012f9e0", "hex")))
                    })
                })
            })

            describe("Identities", () => {
                describe("Soft Derivations", () => {
                    it("\(OK) Derive m'/44'/0'/0'/0/0 Identity Key", async () => {
                        const key: Uint8Array = await cryptoService.keyGen(KeyContext.Identity, 0, 0)
                        console.log(`hex: ${Buffer.from(key).toString("hex")}`)

                        expect(key).toEqual(new Uint8Array(Buffer.from("66a6adcf9d6723211d820645e863ebabb0d182908865a924f5c6bb6a9a96f0fd", "hex")))
                    })
            
                    it("\(OK) Derive m'/44'/0'/0'/0/1 Identity Key", async () => {
                        const key: Uint8Array = await cryptoService.keyGen(KeyContext.Identity, 0, 1)
                        console.log(`hex: ${Buffer.from(key).toString("hex")}`)

                        expect(key).toEqual(new Uint8Array(Buffer.from("d1a696d7a897c6353c721c5631adfcd451d347314a291cbbd7f4ddace6b6400e", "hex")))
                    })
            
                    it("\(OK) Derive m'/44'/0'/0'/0/2 Identity Key", async () => {
                        const key: Uint8Array = await cryptoService.keyGen(KeyContext.Identity, 0, 2)
                        console.log(`hex: ${Buffer.from(key).toString("hex")}`)

                        expect(key).toEqual(new Uint8Array(Buffer.from("85af3a9acda6c7f55e4e0b8ba961076370be1e9b2971e41164fd7d89095836f8", "hex")))
                    })
                })

                describe("Hard Derivations", () => {
                    it("\(OK) Derive m'/44'/0'/1'/0/0 Identity Key", async () => {
                        const key: Uint8Array = await cryptoService.keyGen(KeyContext.Identity, 1, 0)
                        console.log(`hex: ${Buffer.from(key).toString("hex")}`)

                        expect(key).toEqual(new Uint8Array(Buffer.from("62d3d4d9377b03eceb0d6623e9c6df4c162395f4173f94181573052fff25573c", "hex")))
                    })
        
                    it("\(OK) Derive m'/44'/0'/2'/0/1 Identity Key", async () => {
                        const key: Uint8Array = await cryptoService.keyGen(KeyContext.Identity, 2, 1)
                        console.log(`hex: ${Buffer.from(key).toString("hex")}`)

                        expect(key).toEqual(new Uint8Array(Buffer.from("0ff559fc87f9fb27efe6d7d817bd350e815f41a71fa19ed63807aba7ad184e72", "hex")))
                    })
                })
            })

        it("\(OK) Sign Arbitrary Message", async () => {
            const firstKey: Uint8Array = await cryptoService.keyGen(KeyContext.Address, 0, 0)

            const message: Uint8Array = Buffer.from("Hello World")
            const signature: Uint8Array = await cryptoService.signData(KeyContext.Address,0, 0, message)
            expect(signature).toHaveLength(64)

            const isValid: boolean = await cryptoService.verifyWithPublicKey(signature, message, firstKey)
            expect(isValid).toBe(true)
        })

        it("\(OK) ECDH", async () => {
            const aliceKey: Uint8Array = await cryptoService.keyGen(KeyContext.Address, 0, 0)
            const bobKey: Uint8Array = await cryptoService.keyGen(KeyContext.Address, 0, 1)

            const aliceSharedSecret: Uint8Array = await cryptoService.ECDH(KeyContext.Address, 0, 0, bobKey)
            const bobSharedSecret: Uint8Array = await cryptoService.ECDH(KeyContext.Address, 0, 1, aliceKey)

            expect(aliceSharedSecret).toEqual(bobSharedSecret)
        })

        it("\(OK) ECDH, Encrypt and Decrypt", async () => {
            const aliceKey: Uint8Array = await cryptoService.keyGen(KeyContext.Identity, 0, 0)
            const bobKey: Uint8Array = await cryptoService.keyGen(KeyContext.Identity, 0, 1)

            const aliceSharedSecret: Uint8Array = await cryptoService.ECDH(KeyContext.Identity, 0, 0, bobKey)
            const bobSharedSecret: Uint8Array = await cryptoService.ECDH(KeyContext.Identity, 0, 1, aliceKey)

            expect(aliceSharedSecret).toEqual(bobSharedSecret)

            const message: Uint8Array = new Uint8Array(Buffer.from("Hello World"))
            const nonce: Uint8Array = randomBytes(crypto_secretbox_NONCEBYTES)

            // encrypt
            const cipherText: Uint8Array = crypto_secretbox_easy(message, nonce, aliceSharedSecret)

            // decrypt
            const plainText: Uint8Array = crypto_secretbox_open_easy(cipherText, nonce, bobSharedSecret)
            expect(plainText).toEqual(message)
        })

        it("Libsodium example ECDH", async () => {
            await ready
            // keypair
            const alice: KeyPair = crypto_sign_keypair()

            const alicePvtKey: Uint8Array = alice.privateKey
            const alicePubKey: Uint8Array = alice.publicKey

            const aliceXPvt: Uint8Array = crypto_sign_ed25519_sk_to_curve25519(alicePvtKey)
            const aliceXPub: Uint8Array = crypto_sign_ed25519_pk_to_curve25519(alicePubKey)
    
            // bob
            const bob: KeyPair = crypto_sign_keypair()
            
            const bobPvtKey: Uint8Array = bob.privateKey
            const bobPubKey: Uint8Array = bob.publicKey

            const bobXPvt: Uint8Array = crypto_sign_ed25519_sk_to_curve25519(bobPvtKey)
            const bobXPub: Uint8Array = crypto_sign_ed25519_pk_to_curve25519(bobPubKey)

            // shared secret
            const aliceSecret: Uint8Array = crypto_scalarmult(aliceXPvt, bobXPub)
            const bobSecret: Uint8Array = crypto_scalarmult(bobXPvt, aliceXPub)
            expect(aliceSecret).toEqual(bobSecret)

            const aliceSharedSecret: CryptoKX = crypto_kx_client_session_keys(aliceXPub, aliceXPvt, bobXPub)
            const bobSharedSecret: CryptoKX = crypto_kx_server_session_keys(bobXPub, bobXPvt, aliceXPub)

            // bilateral encryption channels
            expect(aliceSharedSecret.sharedRx).toEqual(bobSharedSecret.sharedTx)
            expect(bobSharedSecret.sharedTx).toEqual(aliceSharedSecret.sharedRx)
        })
    })

    describe("\(Identity) Context", () => {

    })
})
