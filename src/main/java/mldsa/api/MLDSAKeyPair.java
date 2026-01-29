package mldsa.api;

/**
 * ML-DSA key pair containing both public and private keys.
 *
 * @param publicKey the public key
 * @param privateKey the private key
 */
public record MLDSAKeyPair(MLDSAPublicKey publicKey, MLDSAPrivateKey privateKey) {

    /**
     * Creates a key pair with validation.
     */
    public MLDSAKeyPair {
        if (publicKey == null) {
            throw new IllegalArgumentException("Public key cannot be null");
        }
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }
        if (publicKey.parameterSet() != privateKey.parameterSet()) {
            throw new IllegalArgumentException("Key parameter sets must match");
        }
    }

    /**
     * Gets the parameter set for this key pair.
     *
     * @return the parameter set
     */
    public MLDSAParameterSet parameterSet() {
        return publicKey.parameterSet();
    }

    /**
     * Securely erases the private key material.
     */
    public void destroyPrivateKey() {
        privateKey.destroy();
    }
}
