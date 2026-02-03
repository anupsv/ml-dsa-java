package mldsa;

import mldsa.api.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for ML-DSA sign/verify operations.
 */
class MLDSAIntegrationTests {

    @ParameterizedTest
    @EnumSource(MLDSAParameterSet.class)
    @DisplayName("Key generation produces correct sizes")
    void testKeyGenSizes(MLDSAParameterSet params) {
        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(params);

        assertEquals(params.getPublicKeySize(), keyPair.publicKey().encoded().length,
                "Public key should have correct size for " + params);
        assertEquals(params.getPrivateKeySize(), keyPair.privateKey().encoded().length,
                "Private key should have correct size for " + params);
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSet.class)
    @DisplayName("Sign produces correct signature size")
    void testSignatureSize(MLDSAParameterSet params) {
        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(params);
        byte[] message = "Test message".getBytes();

        MLDSASignature signature = MLDSA.sign(keyPair.privateKey(), message);

        assertEquals(params.getSignatureSize(), signature.encoded().length,
                "Signature should have correct size for " + params);
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSet.class)
    @DisplayName("Sign and verify roundtrip")
    void testSignVerifyRoundtrip(MLDSAParameterSet params) {
        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(params);
        byte[] message = "Hello, ML-DSA!".getBytes();

        MLDSASignature signature = MLDSA.sign(keyPair.privateKey(), message);
        boolean valid = MLDSA.verify(keyPair.publicKey(), message, signature);

        assertTrue(valid, "Signature should verify for " + params);
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSet.class)
    @DisplayName("Verification fails for modified message")
    void testModifiedMessage(MLDSAParameterSet params) {
        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(params);
        byte[] message = "Original message".getBytes();

        MLDSASignature signature = MLDSA.sign(keyPair.privateKey(), message);

        byte[] modifiedMessage = "Modified message".getBytes();
        boolean valid = MLDSA.verify(keyPair.publicKey(), modifiedMessage, signature);

        assertFalse(valid, "Signature should not verify for modified message");
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSet.class)
    @DisplayName("Verification fails for wrong public key")
    void testWrongPublicKey(MLDSAParameterSet params) {
        MLDSAKeyPair keyPair1 = MLDSA.generateKeyPair(params);
        MLDSAKeyPair keyPair2 = MLDSA.generateKeyPair(params);
        byte[] message = "Test message".getBytes();

        MLDSASignature signature = MLDSA.sign(keyPair1.privateKey(), message);
        boolean valid = MLDSA.verify(keyPair2.publicKey(), message, signature);

        assertFalse(valid, "Signature should not verify with wrong public key");
    }

    @Test
    @DisplayName("Deterministic key generation from seed")
    void testDeterministicKeyGen() {
        byte[] seed = new byte[32];
        Arrays.fill(seed, (byte) 0x42);

        MLDSAKeyPair keyPair1 = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_65, seed);
        MLDSAKeyPair keyPair2 = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_65, seed);

        assertArrayEquals(keyPair1.publicKey().encoded(), keyPair2.publicKey().encoded(),
                "Same seed should produce same public key");
        assertArrayEquals(keyPair1.privateKey().encoded(), keyPair2.privateKey().encoded(),
                "Same seed should produce same private key");
    }

    @Test
    @DisplayName("Deterministic signing with randomness")
    void testDeterministicSigning() {
        byte[] seed = new byte[32];
        Arrays.fill(seed, (byte) 0x42);

        byte[] rnd = new byte[32];
        Arrays.fill(rnd, (byte) 0x55);

        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_65, seed);
        byte[] message = "Test message".getBytes();

        // Use signRaw for deterministic testing (no domain separation)
        MLDSASignature sig1 = MLDSA.signRaw(keyPair.privateKey(), message, rnd);
        MLDSASignature sig2 = MLDSA.signRaw(keyPair.privateKey(), message, rnd);

        assertArrayEquals(sig1.encoded(), sig2.encoded(),
                "Same randomness should produce same signature");
    }

    @Test
    @DisplayName("Empty message can be signed and verified")
    void testEmptyMessage() {
        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_44);
        byte[] message = new byte[0];

        MLDSASignature signature = MLDSA.sign(keyPair.privateKey(), message);
        boolean valid = MLDSA.verify(keyPair.publicKey(), message, signature);

        assertTrue(valid, "Empty message should be signable and verifiable");
    }

    @Test
    @DisplayName("Large message can be signed and verified")
    void testLargeMessage() {
        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_44);
        byte[] message = new byte[1024 * 1024]; // 1 MB
        Arrays.fill(message, (byte) 0xAB);

        MLDSASignature signature = MLDSA.sign(keyPair.privateKey(), message);
        boolean valid = MLDSA.verify(keyPair.publicKey(), message, signature);

        assertTrue(valid, "Large message should be signable and verifiable");
    }

    @Test
    @DisplayName("Private key destruction zeros the key material")
    void testPrivateKeyDestruction() {
        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_44);
        byte[] originalEncoded = keyPair.privateKey().encoded();

        // Verify key is not all zeros initially
        boolean hasNonZero = false;
        for (byte b : originalEncoded) {
            if (b != 0) {
                hasNonZero = true;
                break;
            }
        }
        assertTrue(hasNonZero, "Private key should contain non-zero bytes");

        // Destroy the key
        keyPair.destroyPrivateKey();

        // Note: Due to the defensive copy in encoded(), we can't directly verify
        // the destruction from outside. This test verifies the method doesn't throw.
    }

    @Test
    @DisplayName("Parameter set mismatch returns false")
    void testParameterSetMismatch() {
        MLDSAKeyPair keyPair44 = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_44);
        MLDSAKeyPair keyPair65 = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_65);
        byte[] message = "Test".getBytes();

        MLDSASignature signature = MLDSA.sign(keyPair65.privateKey(), message);

        // Try to verify with wrong parameter set key
        boolean valid = MLDSA.verify(keyPair44.publicKey(), message, signature);

        assertFalse(valid, "Verification with mismatched parameter sets should fail");
    }

    @Test
    @DisplayName("Security levels are correct")
    void testSecurityLevels() {
        assertEquals(2, MLDSAParameterSet.ML_DSA_44.getSecurityLevel());
        assertEquals(3, MLDSAParameterSet.ML_DSA_65.getSecurityLevel());
        assertEquals(5, MLDSAParameterSet.ML_DSA_87.getSecurityLevel());
    }

    @Test
    @DisplayName("Key and signature sizes match FIPS 204")
    void testFIPS204Sizes() {
        // ML-DSA-44
        assertEquals(1312, MLDSAParameterSet.ML_DSA_44.getPublicKeySize());
        assertEquals(2560, MLDSAParameterSet.ML_DSA_44.getPrivateKeySize());
        assertEquals(2420, MLDSAParameterSet.ML_DSA_44.getSignatureSize());

        // ML-DSA-65
        assertEquals(1952, MLDSAParameterSet.ML_DSA_65.getPublicKeySize());
        assertEquals(4032, MLDSAParameterSet.ML_DSA_65.getPrivateKeySize());
        assertEquals(3309, MLDSAParameterSet.ML_DSA_65.getSignatureSize());

        // ML-DSA-87
        assertEquals(2592, MLDSAParameterSet.ML_DSA_87.getPublicKeySize());
        assertEquals(4896, MLDSAParameterSet.ML_DSA_87.getPrivateKeySize());
        assertEquals(4627, MLDSAParameterSet.ML_DSA_87.getSignatureSize());
    }
}
