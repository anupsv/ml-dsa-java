package io.salvador.mldsa.api;

import io.salvador.mldsa.ct.ConstantTime;

import java.util.Arrays;

/**
 * ML-DSA private key.
 * Contains the encoded private key bytes and associated parameter set.
 *
 * <p>WARNING: Private keys contain sensitive cryptographic material.
 * Handle with care and securely erase when no longer needed.</p>
 *
 * @param parameterSet the parameter set this key was generated for
 * @param encoded the encoded private key bytes
 */
public record MLDSAPrivateKey(MLDSAParameterSet parameterSet, byte[] encoded) {

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
     */
    public void destroy() {
        ConstantTime.zero(encoded);
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
