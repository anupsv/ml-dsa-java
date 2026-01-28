package io.salvador.mldsa.api;

import io.salvador.mldsa.core.KeyGen;
import io.salvador.mldsa.core.Sign;
import io.salvador.mldsa.core.Verify;
import io.salvador.mldsa.params.Parameters;

/**
 * Main entry point for ML-DSA (Module-Lattice-Based Digital Signature Algorithm).
 *
 * <p>ML-DSA is a post-quantum digital signature scheme standardized in FIPS 204.
 * It is based on the hardness of the Module Learning With Errors (MLWE) and
 * Module Short Integer Solution (MSIS) problems.</p>
 *
 * <h2>Example Usage</h2>
 * <pre>{@code
 * // Generate a key pair
 * MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_65);
 *
 * // Sign a message
 * byte[] message = "Hello, World!".getBytes();
 * MLDSASignature signature = MLDSA.sign(keyPair.privateKey(), message);
 *
 * // Verify the signature
 * boolean valid = MLDSA.verify(keyPair.publicKey(), message, signature);
 * }</pre>
 *
 * <h2>Parameter Sets</h2>
 * <ul>
 *   <li><b>ML_DSA_44</b>: NIST Security Level 2 (equivalent to SHA-256)</li>
 *   <li><b>ML_DSA_65</b>: NIST Security Level 3 (equivalent to AES-192)</li>
 *   <li><b>ML_DSA_87</b>: NIST Security Level 5 (equivalent to AES-256)</li>
 * </ul>
 *
 * <h2>Security Considerations</h2>
 * <ul>
 *   <li>All cryptographic operations are implemented in constant time to prevent timing attacks</li>
 *   <li>Private keys should be securely erased when no longer needed using {@link MLDSAPrivateKey#destroy()}</li>
 *   <li>Use {@link java.security.SecureRandom} for any additional randomness requirements</li>
 * </ul>
 */
public final class MLDSA {

    private MLDSA() {
        // Utility class
    }

    /**
     * Generates a new ML-DSA key pair using the specified parameter set.
     *
     * @param parameterSet the parameter set (security level)
     * @return the generated key pair
     */
    public static MLDSAKeyPair generateKeyPair(MLDSAParameterSet parameterSet) {
        Parameters params = parameterSet.getParameters();
        byte[][] keys = KeyGen.generate(params);

        MLDSAPublicKey publicKey = new MLDSAPublicKey(parameterSet, keys[0]);
        MLDSAPrivateKey privateKey = new MLDSAPrivateKey(parameterSet, keys[1]);

        return new MLDSAKeyPair(publicKey, privateKey);
    }

    /**
     * Generates a new ML-DSA key pair from a specific seed.
     * This is primarily for testing and deterministic key derivation.
     *
     * @param parameterSet the parameter set (security level)
     * @param seed the 32-byte seed
     * @return the generated key pair
     * @throws IllegalArgumentException if seed is not 32 bytes
     */
    public static MLDSAKeyPair generateKeyPair(MLDSAParameterSet parameterSet, byte[] seed) {
        if (seed == null || seed.length != 32) {
            throw new IllegalArgumentException("Seed must be exactly 32 bytes");
        }

        Parameters params = parameterSet.getParameters();
        byte[][] keys = KeyGen.generate(params, seed);

        MLDSAPublicKey publicKey = new MLDSAPublicKey(parameterSet, keys[0]);
        MLDSAPrivateKey privateKey = new MLDSAPrivateKey(parameterSet, keys[1]);

        return new MLDSAKeyPair(publicKey, privateKey);
    }

    /**
     * Signs a message using the given private key.
     *
     * @param privateKey the private key to sign with
     * @param message the message to sign
     * @return the signature
     * @throws MLDSAException if signing fails
     */
    public static MLDSASignature sign(MLDSAPrivateKey privateKey, byte[] message) {
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }
        if (message == null) {
            throw new IllegalArgumentException("Message cannot be null");
        }

        Parameters params = privateKey.parameterSet().getParameters();
        byte[] sigBytes = Sign.sign(params, privateKey.encodedInternal(), message);

        return new MLDSASignature(privateKey.parameterSet(), sigBytes);
    }

    /**
     * Signs a message with a specific random value (for deterministic testing).
     *
     * @param privateKey the private key to sign with
     * @param message the message to sign
     * @param randomness 32-byte randomness for hedged signing
     * @return the signature
     * @throws MLDSAException if signing fails
     */
    public static MLDSASignature sign(MLDSAPrivateKey privateKey, byte[] message, byte[] randomness) {
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }
        if (message == null) {
            throw new IllegalArgumentException("Message cannot be null");
        }
        if (randomness == null || randomness.length != 32) {
            throw new IllegalArgumentException("Randomness must be exactly 32 bytes");
        }

        Parameters params = privateKey.parameterSet().getParameters();
        byte[] sigBytes = Sign.sign(params, privateKey.encodedInternal(), message, randomness);

        return new MLDSASignature(privateKey.parameterSet(), sigBytes);
    }

    /**
     * Verifies a signature against a message and public key.
     *
     * @param publicKey the public key
     * @param message the signed message
     * @param signature the signature to verify
     * @return true if the signature is valid, false otherwise
     */
    public static boolean verify(MLDSAPublicKey publicKey, byte[] message, MLDSASignature signature) {
        if (publicKey == null) {
            throw new IllegalArgumentException("Public key cannot be null");
        }
        if (message == null) {
            throw new IllegalArgumentException("Message cannot be null");
        }
        if (signature == null) {
            throw new IllegalArgumentException("Signature cannot be null");
        }
        if (publicKey.parameterSet() != signature.parameterSet()) {
            return false; // Parameter set mismatch
        }

        Parameters params = publicKey.parameterSet().getParameters();
        return Verify.verify(params, publicKey.encodedInternal(), message, signature.encodedInternal());
    }

    /**
     * Verifies a signature given raw byte arrays.
     * Convenience method when working with serialized keys and signatures.
     *
     * @param parameterSet the parameter set
     * @param publicKeyBytes the encoded public key
     * @param message the signed message
     * @param signatureBytes the encoded signature
     * @return true if the signature is valid, false otherwise
     */
    public static boolean verify(MLDSAParameterSet parameterSet,
                                 byte[] publicKeyBytes,
                                 byte[] message,
                                 byte[] signatureBytes) {
        MLDSAPublicKey publicKey = new MLDSAPublicKey(parameterSet, publicKeyBytes);
        MLDSASignature signature = new MLDSASignature(parameterSet, signatureBytes);
        return verify(publicKey, message, signature);
    }
}
