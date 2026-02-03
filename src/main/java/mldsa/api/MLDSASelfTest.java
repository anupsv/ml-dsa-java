package mldsa.api;

import mldsa.ct.ConstantTime;
import mldsa.hash.Shake;

/**
 * FIPS 140-3 self-tests for ML-DSA.
 *
 * <p>This class provides Known Answer Tests (KAT) and health checks to verify
 * the correct operation of the ML-DSA implementation. These tests should be run:
 * <ul>
 *   <li>At library initialization (power-on self-test)</li>
 *   <li>Periodically during operation (conditional self-test)</li>
 *   <li>After any suspected tampering or fault</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * // Run all self-tests at startup
 * MLDSASelfTest.runAllTests();
 *
 * // Or run individual tests
 * MLDSASelfTest.testKeyGeneration();
 * MLDSASelfTest.testSignVerify();
 * MLDSASelfTest.testShake256();
 * }</pre>
 *
 * <h2>FIPS 140-3 Compliance</h2>
 * <p>These tests implement the following FIPS 140-3 requirements:</p>
 * <ul>
 *   <li><b>Power-on self-tests</b>: Verify algorithm correctness at startup</li>
 *   <li><b>Known Answer Tests</b>: Compare outputs against pre-computed values</li>
 *   <li><b>Pairwise consistency</b>: Verify sign/verify with generated keys</li>
 *   <li><b>Integrity checks</b>: Verify critical constants haven't been modified</li>
 * </ul>
 */
public final class MLDSASelfTest {

    private MLDSASelfTest() {
        // Utility class
    }

    /** Flag indicating whether self-tests have passed */
    private static volatile boolean selfTestsPassed = false;

    /** Lock for thread-safe initialization */
    private static final Object LOCK = new Object();

    // ==================== Known Answer Test Vectors ====================
    // These are pre-computed values for deterministic testing

    /** KAT seed for key generation (from ACVP test vectors) */
    private static final byte[] KAT_SEED = hexToBytes(
        "93EF2E6EF1FB08999D142ABE0295482370D3F43BDB254A78E2B0D5168ECA065F"
    );

    /** Expected public key prefix (rho = first 32 bytes) for ML-DSA-44 with KAT_SEED (from ACVP) */
    private static final byte[] KAT_PK_PREFIX_44 = hexToBytes(
        "BC5FF810EB089048B8AB3020A7BD3B16C0E0CA3D6B97E4646C2CCAE0BBF19EF7"
    );

    /** KAT message for signing */
    private static final byte[] KAT_MESSAGE = "FIPS 140-3 self-test message".getBytes();

    /** KAT randomness for deterministic signing */
    private static final byte[] KAT_RANDOMNESS = hexToBytes(
        "0000000000000000000000000000000000000000000000000000000000000000"
    );

    /** Expected SHAKE256 output for "test" input with 24-byte output */
    private static final byte[] KAT_SHAKE256_OUTPUT = hexToBytes(
        "b54ff7255705a71ee2925e4a3e30e41aed489a579d5595e0"
    );

    // ==================== Public API ====================

    /**
     * Runs all self-tests and throws an exception if any fail.
     *
     * <p>This method is idempotent - subsequent calls after a successful run
     * will return immediately without re-running the tests.
     *
     * @throws MLDSASelfTestException if any self-test fails
     */
    public static void runAllTests() {
        synchronized (LOCK) {
            if (selfTestsPassed) {
                return; // Already passed
            }

            try {
                testIntegrity();
                testShake256();
                testKeyGeneration();
                testSignVerify();
                testPairwiseConsistency();

                selfTestsPassed = true;
            } catch (MLDSASelfTestException e) {
                selfTestsPassed = false;
                throw e;
            }
        }
    }

    /**
     * Checks if self-tests have been run and passed.
     *
     * @return true if all self-tests have passed
     */
    public static boolean hasPassed() {
        return selfTestsPassed;
    }

    /**
     * Forces self-tests to run again on next call to {@link #runAllTests()}.
     * Use this after any suspected tampering or to implement periodic re-testing.
     */
    public static void reset() {
        synchronized (LOCK) {
            selfTestsPassed = false;
        }
    }

    // ==================== Individual Tests ====================

    /**
     * Tests critical constants haven't been modified.
     *
     * @throws MLDSASelfTestException if integrity check fails
     */
    public static void testIntegrity() {
        // Verify prime modulus Q
        if (mldsa.params.Parameters.Q != 8380417) {
            throw new MLDSASelfTestException("Integrity check failed: Q constant modified");
        }

        // Verify polynomial degree N
        if (mldsa.params.Parameters.N != 256) {
            throw new MLDSASelfTestException("Integrity check failed: N constant modified");
        }

        // Verify D constant
        if (mldsa.params.Parameters.D != 13) {
            throw new MLDSASelfTestException("Integrity check failed: D constant modified");
        }

        // Verify parameter set sizes
        if (MLDSAParameterSet.ML_DSA_44.getPublicKeySize() != 1312) {
            throw new MLDSASelfTestException("Integrity check failed: ML-DSA-44 public key size");
        }
        if (MLDSAParameterSet.ML_DSA_65.getPublicKeySize() != 1952) {
            throw new MLDSASelfTestException("Integrity check failed: ML-DSA-65 public key size");
        }
        if (MLDSAParameterSet.ML_DSA_87.getPublicKeySize() != 2592) {
            throw new MLDSASelfTestException("Integrity check failed: ML-DSA-87 public key size");
        }
    }

    /**
     * Tests SHAKE256 implementation with Known Answer Test.
     *
     * @throws MLDSASelfTestException if SHAKE256 produces incorrect output
     */
    public static void testShake256() {
        byte[] input = "test".getBytes();
        byte[] output = Shake.shake256(input, 24);

        if (!ConstantTime.arraysEqual(output, KAT_SHAKE256_OUTPUT)) {
            throw new MLDSASelfTestException("SHAKE256 KAT failed: output mismatch");
        }
    }

    /**
     * Tests deterministic key generation with Known Answer Test.
     *
     * @throws MLDSASelfTestException if key generation produces incorrect output
     */
    public static void testKeyGeneration() {
        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_44, KAT_SEED);

        // Verify public key prefix matches expected value (rho is first 32 bytes)
        byte[] pkBytes = keyPair.publicKey().encoded();
        byte[] pkPrefix = new byte[32];
        System.arraycopy(pkBytes, 0, pkPrefix, 0, 32);

        if (!ConstantTime.arraysEqual(pkPrefix, KAT_PK_PREFIX_44)) {
            throw new MLDSASelfTestException("Key generation KAT failed: public key prefix mismatch");
        }

        // Clean up
        keyPair.destroyPrivateKey();
    }

    /**
     * Tests sign/verify roundtrip with deterministic values.
     *
     * @throws MLDSASelfTestException if sign/verify fails
     */
    public static void testSignVerify() {
        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_44, KAT_SEED);

        try {
            // Sign with deterministic randomness using the raw API (for reproducible KAT)
            @SuppressWarnings("deprecation")
            MLDSASignature signature = MLDSA.signRaw(keyPair.privateKey(), KAT_MESSAGE, KAT_RANDOMNESS);

            // Verify signature using raw API (consistent with signing)
            @SuppressWarnings("deprecation")
            boolean valid = MLDSA.verifyRaw(MLDSAParameterSet.ML_DSA_44,
                    keyPair.publicKey().encoded(), KAT_MESSAGE, signature.encoded());
            if (!valid) {
                throw new MLDSASelfTestException("Sign/verify KAT failed: signature didn't verify");
            }

            // Verify wrong message fails
            byte[] wrongMessage = "Wrong message".getBytes();
            @SuppressWarnings("deprecation")
            boolean wrongValid = MLDSA.verifyRaw(MLDSAParameterSet.ML_DSA_44,
                    keyPair.publicKey().encoded(), wrongMessage, signature.encoded());
            if (wrongValid) {
                throw new MLDSASelfTestException("Sign/verify KAT failed: wrong message verified");
            }
        } finally {
            keyPair.destroyPrivateKey();
        }
    }

    /**
     * Tests pairwise consistency - that a freshly generated key pair works.
     *
     * @throws MLDSASelfTestException if pairwise consistency check fails
     */
    public static void testPairwiseConsistency() {
        // Test all parameter sets
        for (MLDSAParameterSet params : MLDSAParameterSet.values()) {
            testPairwiseConsistencyForParams(params);
        }
    }

    private static void testPairwiseConsistencyForParams(MLDSAParameterSet params) {
        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(params);

        try {
            byte[] message = ("Pairwise consistency test for " + params).getBytes();

            // Sign
            MLDSASignature signature = MLDSA.sign(keyPair.privateKey(), message);

            // Verify
            boolean valid = MLDSA.verify(keyPair.publicKey(), message, signature);
            if (!valid) {
                throw new MLDSASelfTestException(
                    "Pairwise consistency failed for " + params + ": signature didn't verify");
            }

            // Verify sizes
            if (keyPair.publicKey().encoded().length != params.getPublicKeySize()) {
                throw new MLDSASelfTestException(
                    "Pairwise consistency failed for " + params + ": wrong public key size");
            }
            if (keyPair.privateKey().encoded().length != params.getPrivateKeySize()) {
                throw new MLDSASelfTestException(
                    "Pairwise consistency failed for " + params + ": wrong private key size");
            }
            if (signature.encoded().length != params.getSignatureSize()) {
                throw new MLDSASelfTestException(
                    "Pairwise consistency failed for " + params + ": wrong signature size");
            }
        } finally {
            keyPair.destroyPrivateKey();
        }
    }

    // ==================== Continuous Health Tests ====================

    /**
     * Performs a lightweight health check suitable for continuous testing.
     * This is faster than full self-tests and can be called periodically.
     *
     * @throws MLDSASelfTestException if health check fails
     */
    public static void healthCheck() {
        // Quick SHAKE256 test
        byte[] output = Shake.shake256("health".getBytes(), 8);
        if (output.length != 8) {
            throw new MLDSASelfTestException("Health check failed: SHAKE256 output length wrong");
        }

        // Quick constant check
        if (mldsa.params.Parameters.Q != 8380417) {
            throw new MLDSASelfTestException("Health check failed: Q constant modified");
        }
    }

    // ==================== Utility Methods ====================

    /**
     * Converts a hexadecimal string to a byte array.
     */
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Exception thrown when a self-test fails.
     */
    public static class MLDSASelfTestException extends RuntimeException {
        public MLDSASelfTestException(String message) {
            super(message);
        }
    }
}
