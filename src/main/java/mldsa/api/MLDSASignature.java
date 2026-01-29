package mldsa.api;

import mldsa.ct.ConstantTime;

import java.util.Arrays;

/**
 * ML-DSA signature.
 * Contains the encoded signature bytes and associated parameter set.
 *
 * @param parameterSet the parameter set used for signing
 * @param encoded the encoded signature bytes
 */
public record MLDSASignature(MLDSAParameterSet parameterSet, byte[] encoded) {

    /**
     * Creates a signature with validation.
     */
    public MLDSASignature {
        if (encoded == null) {
            throw new IllegalArgumentException("Encoded signature cannot be null");
        }
        if (encoded.length != parameterSet.getSignatureSize()) {
            throw new IllegalArgumentException(
                    "Invalid signature size: expected " + parameterSet.getSignatureSize() +
                    ", got " + encoded.length);
        }
        // Defensive copy
        encoded = encoded.clone();
    }

    /**
     * Returns the encoded signature bytes.
     * Note: Returns a defensive copy.
     *
     * @return the encoded signature bytes
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
        if (!(obj instanceof MLDSASignature other)) return false;
        return this.parameterSet == other.parameterSet &&
               ConstantTime.arraysEqual(this.encoded, other.encoded);
    }

    @Override
    public int hashCode() {
        return 31 * parameterSet.hashCode() + Arrays.hashCode(encoded);
    }

    @Override
    public String toString() {
        return "MLDSASignature[" + parameterSet + ", " + encoded.length + " bytes]";
    }
}
