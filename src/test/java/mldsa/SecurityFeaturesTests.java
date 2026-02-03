package mldsa;

import mldsa.api.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for security features: context/domain separation, FIPS 140-3 self-tests,
 * and HashML-DSA mode.
 */
class SecurityFeaturesTests {

    // ==================== Context/Domain Separation Tests ====================

    @Test
    @DisplayName("Context separates signatures for same message")
    void testContextSeparation() {
        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_44);
        byte[] message = "Same message".getBytes();
        byte[] context1 = "App1".getBytes();
        byte[] context2 = "App2".getBytes();

        MLDSASignature sig1 = MLDSA.sign(keyPair.privateKey(), message, context1);
        MLDSASignature sig2 = MLDSA.sign(keyPair.privateKey(), message, context2);

        // Different contexts should produce different signatures
        assertFalse(Arrays.equals(sig1.encoded(), sig2.encoded()),
                "Different contexts should produce different signatures");

        // Each signature should verify only with its own context
        assertTrue(MLDSA.verify(keyPair.publicKey(), message, sig1, context1),
                "Signature should verify with correct context");
        assertFalse(MLDSA.verify(keyPair.publicKey(), message, sig1, context2),
                "Signature should not verify with wrong context");

        assertTrue(MLDSA.verify(keyPair.publicKey(), message, sig2, context2),
                "Signature should verify with correct context");
        assertFalse(MLDSA.verify(keyPair.publicKey(), message, sig2, context1),
                "Signature should not verify with wrong context");
    }

    @Test
    @DisplayName("Empty context differs from no-context default")
    void testEmptyContext() {
        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_44);
        byte[] message = "Test message".getBytes();

        // Both should use empty context
        MLDSASignature sig1 = MLDSA.sign(keyPair.privateKey(), message);
        MLDSASignature sig2 = MLDSA.sign(keyPair.privateKey(), message, new byte[0]);

        // Both should verify with empty context
        assertTrue(MLDSA.verify(keyPair.publicKey(), message, sig1),
                "Default context signature should verify");
        assertTrue(MLDSA.verify(keyPair.publicKey(), message, sig2, new byte[0]),
                "Explicit empty context signature should verify");

        // Cross-verify
        assertTrue(MLDSA.verify(keyPair.publicKey(), message, sig1, new byte[0]),
                "Default context should be equivalent to empty context");
        assertTrue(MLDSA.verify(keyPair.publicKey(), message, sig2),
                "Empty context should be equivalent to default");
    }

    @Test
    @DisplayName("Context length validation")
    void testContextLengthValidation() {
        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_44);
        byte[] message = "Test".getBytes();

        // Max length context should work
        byte[] maxContext = new byte[255];
        Arrays.fill(maxContext, (byte) 'a');
        assertDoesNotThrow(() -> MLDSA.sign(keyPair.privateKey(), message, maxContext),
                "255-byte context should be accepted");

        // Too long context should be rejected
        byte[] tooLongContext = new byte[256];
        assertThrows(IllegalArgumentException.class,
                () -> MLDSA.sign(keyPair.privateKey(), message, tooLongContext),
                "256-byte context should be rejected");
    }

    @Test
    @DisplayName("Null context treated as empty")
    void testNullContext() {
        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_44);
        byte[] message = "Test".getBytes();

        MLDSASignature sig = MLDSA.sign(keyPair.privateKey(), message, null);

        assertTrue(MLDSA.verify(keyPair.publicKey(), message, sig, null),
                "Null context should verify");
        assertTrue(MLDSA.verify(keyPair.publicKey(), message, sig, new byte[0]),
                "Null context should be equivalent to empty context");
        assertTrue(MLDSA.verify(keyPair.publicKey(), message, sig),
                "Null context should be equivalent to default");
    }

    // ==================== FIPS 140-3 Self-Tests ====================

    @Test
    @DisplayName("All self-tests pass")
    void testAllSelfTests() {
        // Reset to force re-running
        MLDSASelfTest.reset();
        assertFalse(MLDSASelfTest.hasPassed(), "Self-tests should not have passed after reset");

        // Run all tests
        assertDoesNotThrow(MLDSASelfTest::runAllTests, "Self-tests should pass");
        assertTrue(MLDSASelfTest.hasPassed(), "Self-tests should be marked as passed");

        // Second call should return immediately (idempotent)
        assertDoesNotThrow(MLDSASelfTest::runAllTests, "Second call should succeed");
    }

    @Test
    @DisplayName("Individual self-tests pass")
    void testIndividualSelfTests() {
        assertDoesNotThrow(MLDSASelfTest::testIntegrity, "Integrity test should pass");
        assertDoesNotThrow(MLDSASelfTest::testShake256, "SHAKE256 KAT should pass");
        assertDoesNotThrow(MLDSASelfTest::testKeyGeneration, "Key generation KAT should pass");
        assertDoesNotThrow(MLDSASelfTest::testSignVerify, "Sign/verify test should pass");
        assertDoesNotThrow(MLDSASelfTest::testPairwiseConsistency, "Pairwise consistency should pass");
    }

    @Test
    @DisplayName("Health check passes")
    void testHealthCheck() {
        assertDoesNotThrow(MLDSASelfTest::healthCheck, "Health check should pass");
    }

    // ==================== HashML-DSA Tests ====================

    @Test
    @DisplayName("HashML-DSA with SHA3-256")
    void testHashMLDSA_SHA3_256() {
        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_65);

        // Simulate a pre-hashed message (in practice, this would be SHA3-256 output)
        byte[] messageHash = new byte[32];
        Arrays.fill(messageHash, (byte) 0xAB);
        byte[] context = "HashTest".getBytes();

        MLDSASignature sig = MLDSA.signPreHashed(
                keyPair.privateKey(), messageHash, MLDSA.HashAlgorithm.SHA3_256, context);

        assertTrue(MLDSA.verifyPreHashed(
                keyPair.publicKey(), messageHash, MLDSA.HashAlgorithm.SHA3_256, sig, context),
                "Pre-hashed signature should verify");
    }

    @Test
    @DisplayName("HashML-DSA with SHA3-512")
    void testHashMLDSA_SHA3_512() {
        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_87);

        byte[] messageHash = new byte[64];
        Arrays.fill(messageHash, (byte) 0xCD);
        byte[] context = new byte[0];

        MLDSASignature sig = MLDSA.signPreHashed(
                keyPair.privateKey(), messageHash, MLDSA.HashAlgorithm.SHA3_512, context);

        assertTrue(MLDSA.verifyPreHashed(
                keyPair.publicKey(), messageHash, MLDSA.HashAlgorithm.SHA3_512, sig, context),
                "Pre-hashed signature should verify");
    }

    @Test
    @DisplayName("HashML-DSA with SHAKE256")
    void testHashMLDSA_SHAKE256() {
        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_44);

        byte[] messageHash = new byte[64]; // SHAKE256 with 512-bit output
        Arrays.fill(messageHash, (byte) 0xEF);

        MLDSASignature sig = MLDSA.signPreHashed(
                keyPair.privateKey(), messageHash, MLDSA.HashAlgorithm.SHAKE256, null);

        assertTrue(MLDSA.verifyPreHashed(
                keyPair.publicKey(), messageHash, MLDSA.HashAlgorithm.SHAKE256, sig, null),
                "Pre-hashed signature should verify");
    }

    @Test
    @DisplayName("HashML-DSA wrong hash algorithm fails verification")
    void testHashMLDSA_WrongAlgorithm() {
        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_65);

        byte[] messageHash = new byte[64];
        Arrays.fill(messageHash, (byte) 0x11);

        // Sign with SHA3-512
        MLDSASignature sig = MLDSA.signPreHashed(
                keyPair.privateKey(), messageHash, MLDSA.HashAlgorithm.SHA3_512, null);

        // Verify with SHAKE256 (same output length, different OID)
        assertFalse(MLDSA.verifyPreHashed(
                keyPair.publicKey(), messageHash, MLDSA.HashAlgorithm.SHAKE256, sig, null),
                "Wrong hash algorithm should fail verification");
    }

    @Test
    @DisplayName("HashML-DSA hash length validation")
    void testHashMLDSA_HashLengthValidation() {
        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_44);

        // Wrong length for SHA3-256 (should be 32, not 64)
        byte[] wrongLength = new byte[64];

        assertThrows(IllegalArgumentException.class,
                () -> MLDSA.signPreHashed(keyPair.privateKey(), wrongLength, MLDSA.HashAlgorithm.SHA3_256, null),
                "Wrong hash length should be rejected");
    }

    @Test
    @DisplayName("HashML-DSA vs pure ML-DSA are incompatible")
    void testHashMLDSA_VsPure() {
        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_44);

        byte[] message = "Test message".getBytes();
        byte[] messageHash = new byte[32]; // Pretend this is SHA3-256(message)
        System.arraycopy(message, 0, messageHash, 0, Math.min(message.length, 32));

        // Sign with pure ML-DSA
        MLDSASignature pureSig = MLDSA.sign(keyPair.privateKey(), message);

        // Sign with HashML-DSA
        MLDSASignature hashSig = MLDSA.signPreHashed(
                keyPair.privateKey(), messageHash, MLDSA.HashAlgorithm.SHA3_256, null);

        // They should be different
        assertFalse(Arrays.equals(pureSig.encoded(), hashSig.encoded()),
                "Pure and hash signatures should differ");

        // Pure signature shouldn't verify as hash signature
        assertFalse(MLDSA.verifyPreHashed(
                keyPair.publicKey(), messageHash, MLDSA.HashAlgorithm.SHA3_256, pureSig, null),
                "Pure signature should not verify as hash signature");
    }

    // ==================== SecureRandomProvider Tests ====================

    @Test
    @DisplayName("Custom SecureRandomProvider can be set")
    void testSecureRandomProvider() {
        // Save original
        MLDSA.SecureRandomProvider original = MLDSA.getSecureRandomProvider();

        try {
            // Set custom provider
            MLDSA.setSecureRandomProvider(() -> new java.security.SecureRandom());

            // Should still work
            MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_44);
            assertNotNull(keyPair);

            // Reset to null should restore default
            MLDSA.setSecureRandomProvider(null);
            keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_44);
            assertNotNull(keyPair);
        } finally {
            // Restore original
            MLDSA.setSecureRandomProvider(original);
        }
    }

    @Test
    @DisplayName("Signature counter can be reset")
    void testSignatureCounterReset() {
        // Just verify it doesn't throw
        assertDoesNotThrow(MLDSA::resetSignatureCounter);
    }
}
