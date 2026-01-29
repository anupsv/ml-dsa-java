package mldsa.params;

/**
 * ML-DSA-44 parameter set (NIST Security Level 2).
 * Equivalent security to SHA-256 collision resistance.
 */
public record MLDSA44() implements Parameters {

    /** Singleton instance */
    public static final MLDSA44 INSTANCE = new MLDSA44();

    @Override
    public int k() {
        return 4;
    }

    @Override
    public int l() {
        return 4;
    }

    @Override
    public int eta() {
        return 2;
    }

    @Override
    public int tau() {
        return 39;
    }

    @Override
    public int gamma1() {
        return 1 << 17; // 2^17 = 131072
    }

    @Override
    public int gamma2() {
        return (Q - 1) / 88; // (q-1)/88 = 95232
    }

    @Override
    public int omega() {
        return 80;
    }

    @Override
    public int publicKeyBytes() {
        return 1312;
    }

    @Override
    public int privateKeyBytes() {
        return 2560;
    }

    @Override
    public int signatureBytes() {
        return 2420;
    }

    @Override
    public int lambda() {
        return 128;
    }
}
