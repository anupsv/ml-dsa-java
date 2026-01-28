package io.salvador.mldsa.params;

/**
 * ML-DSA-87 parameter set (NIST Security Level 5).
 * Equivalent security to AES-256 exhaustive key search.
 */
public record MLDSA87() implements Parameters {

    /** Singleton instance */
    public static final MLDSA87 INSTANCE = new MLDSA87();

    @Override
    public int k() {
        return 8;
    }

    @Override
    public int l() {
        return 7;
    }

    @Override
    public int eta() {
        return 2;
    }

    @Override
    public int tau() {
        return 60;
    }

    @Override
    public int gamma1() {
        return 1 << 19; // 2^19 = 524288
    }

    @Override
    public int gamma2() {
        return (Q - 1) / 32; // (q-1)/32 = 261888
    }

    @Override
    public int omega() {
        return 75;
    }

    @Override
    public int publicKeyBytes() {
        return 2592;
    }

    @Override
    public int privateKeyBytes() {
        return 4896;
    }

    @Override
    public int signatureBytes() {
        return 4627;
    }

    @Override
    public int lambda() {
        return 256;
    }
}
