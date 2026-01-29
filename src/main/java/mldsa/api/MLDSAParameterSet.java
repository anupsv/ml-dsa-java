package mldsa.api;

import mldsa.params.MLDSA44;
import mldsa.params.MLDSA65;
import mldsa.params.MLDSA87;
import mldsa.params.Parameters;

/**
 * Enumeration of ML-DSA parameter sets.
 * Provides a convenient way to select the security level.
 */
public enum MLDSAParameterSet {

    /**
     * ML-DSA-44: NIST Security Level 2.
     * Equivalent security to SHA-256 collision resistance.
     */
    ML_DSA_44(MLDSA44.INSTANCE),

    /**
     * ML-DSA-65: NIST Security Level 3.
     * Equivalent security to AES-192 exhaustive key search.
     */
    ML_DSA_65(MLDSA65.INSTANCE),

    /**
     * ML-DSA-87: NIST Security Level 5.
     * Equivalent security to AES-256 exhaustive key search.
     */
    ML_DSA_87(MLDSA87.INSTANCE);

    private final Parameters params;

    MLDSAParameterSet(Parameters params) {
        this.params = params;
    }

    /**
     * Gets the internal parameters object.
     *
     * @return the parameters
     */
    public Parameters getParameters() {
        return params;
    }

    /**
     * Gets the public key size in bytes.
     *
     * @return the public key size
     */
    public int getPublicKeySize() {
        return params.publicKeyBytes();
    }

    /**
     * Gets the private key size in bytes.
     *
     * @return the private key size
     */
    public int getPrivateKeySize() {
        return params.privateKeyBytes();
    }

    /**
     * Gets the signature size in bytes.
     *
     * @return the signature size
     */
    public int getSignatureSize() {
        return params.signatureBytes();
    }

    /**
     * Gets the NIST security level (2, 3, or 5).
     *
     * @return the security level
     */
    public int getSecurityLevel() {
        return switch (this) {
            case ML_DSA_44 -> 2;
            case ML_DSA_65 -> 3;
            case ML_DSA_87 -> 5;
        };
    }
}
