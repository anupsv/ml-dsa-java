package mldsa.api;

import mldsa.ct.ConstantTime;

import java.util.Arrays;

/**
 * ML-DSA public key.
 * Contains the encoded public key bytes and associated parameter set.
 *
 * @param parameterSet the parameter set this key was generated for
 * @param encoded the encoded public key bytes
 */
public record MLDSAPublicKey(MLDSAParameterSet parameterSet, byte[] encoded) {

    /**
     * Creates a public key with validation.
     */
    public MLDSAPublicKey {
        if (encoded == null) {
            throw new IllegalArgumentException("Encoded key cannot be null");
        }
        if (encoded.length != parameterSet.getPublicKeySize()) {
            throw new IllegalArgumentException(
                    "Invalid public key size: expected " + parameterSet.getPublicKeySize() +
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

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof MLDSAPublicKey other)) return false;
        return this.parameterSet == other.parameterSet &&
               ConstantTime.arraysEqual(this.encoded, other.encoded);
    }

    @Override
    public int hashCode() {
        return 31 * parameterSet.hashCode() + Arrays.hashCode(encoded);
    }

    @Override
    public String toString() {
        return "MLDSAPublicKey[" + parameterSet + ", " + encoded.length + " bytes]";
    }
}
