package io.salvador.mldsa.params;

/**
 * ML-DSA-65 parameter set (NIST Security Level 3).
 * Equivalent security to AES-192 exhaustive key search.
 */
public record MLDSA65() implements Parameters {

    /** Singleton instance */
    public static final MLDSA65 INSTANCE = new MLDSA65();

    @Override
    public int k() {
        return 6;
    }

    @Override
    public int l() {
        return 5;
    }

    @Override
    public int eta() {
        return 4;
    }

    @Override
    public int tau() {
        return 49;
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
        return 55;
    }

    @Override
    public int publicKeyBytes() {
        return 1952;
    }

    @Override
    public int privateKeyBytes() {
        return 4032;
    }

    @Override
    public int signatureBytes() {
        return 3309;
    }

    @Override
    public int lambda() {
        return 192;
    }
}
