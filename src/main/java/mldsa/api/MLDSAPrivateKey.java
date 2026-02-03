package mldsa.api;

import mldsa.ct.ConstantTime;

import java.util.Arrays;

/**
 * ML-DSA private key.
 * Contains the encoded private key bytes and associated parameter set.
 *
 * <p>WARNING: Private keys contain sensitive cryptographic material.
 * Handle with care and securely erase when no longer needed.</p>
 *
 * <p>This class implements {@link AutoCloseable} to support try-with-resources:
 * <pre>{@code
 * try (MLDSAPrivateKey privateKey = keyPair.privateKey()) {
 *     MLDSASignature sig = MLDSA.sign(privateKey, message);
 * } // privateKey.destroy() is automatically called
 * }</pre>
 *
 * <p><b>Security Note:</b> Once {@link #destroy()} or {@link #close()} is called,
 * the key material is securely erased. After destruction, {@link #isDestroyed()}
 * returns true, but the key object remains usable (with zeroed content).
 *
 * @param parameterSet the parameter set this key was generated for
 * @param encoded the encoded private key bytes
 */
public record MLDSAPrivateKey(MLDSAParameterSet parameterSet, byte[] encoded) implements AutoCloseable {

    /**
     * Creates a private key with validation.
     */
    public MLDSAPrivateKey {
        if (encoded == null) {
            throw new IllegalArgumentException("Encoded key cannot be null");
        }
        if (encoded.length != parameterSet.getPrivateKeySize()) {
            throw new IllegalArgumentException(
                    "Invalid private key size: expected " + parameterSet.getPrivateKeySize() +
                    ", got " + encoded.length);
        }
        // Defensive copy
        encoded = encoded.clone();
    }

    /**
     * Returns the encoded key bytes.
     * Note: Returns a defensive copy.
     *
     * @return the encoded key bytes
     */
    @Override
    public byte[] encoded() {
        return encoded.clone();
    }

    /**
     * Returns the raw encoded bytes without copying.
     * For internal use only.
     *
     * @return the raw encoded bytes
     */
    byte[] encodedInternal() {
        return encoded;
    }

    /**
     * Securely erases the private key material.
     * After calling this method, the key should not be used.
     *
     * <p>Note: Due to Java's memory model, this may not completely
     * prevent the key material from being recoverable. For maximum
     * security, consider using off-heap memory.</p>
     *
     * <p>This method is idempotent - calling it multiple times has no additional effect.
     */
    public void destroy() {
        ConstantTime.zero(encoded);
    }

    /**
     * Implements {@link AutoCloseable#close()} by calling {@link #destroy()}.
     * This enables use of try-with-resources for automatic key cleanup.
     *
     * <pre>{@code
     * try (MLDSAPrivateKey key = keyPair.privateKey()) {
     *     // use key for signing
     * } // key is automatically destroyed here
     * }</pre>
     */
    @Override
    public void close() {
        destroy();
    }

    /**
     * Checks if this key has been destroyed.
     *
     * <p>Note: This check is best-effort. Due to Java's memory model,
     * the key bytes may have been zeroed but still be accessible through
     * other references or in JVM memory.
     *
     * @return true if {@link #destroy()} has been called, false otherwise
     */
    public boolean isDestroyed() {
        // Check if all bytes are zero (indicates destruction)
        for (byte b : encoded) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof MLDSAPrivateKey other)) return false;
        return this.parameterSet == other.parameterSet &&
               ConstantTime.arraysEqual(this.encoded, other.encoded);
    }

    @Override
    public int hashCode() {
        return 31 * parameterSet.hashCode() + Arrays.hashCode(encoded);
    }

    @Override
    public String toString() {
        // Don't expose key material in toString
        return "MLDSAPrivateKey[" + parameterSet + "]";
    }
}
