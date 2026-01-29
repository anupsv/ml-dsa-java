package mldsa.params;

/**
 * Sealed interface defining ML-DSA parameters per FIPS 204.
 * All three parameter sets (ML-DSA-44, ML-DSA-65, ML-DSA-87) implement this interface.
 */
public sealed interface Parameters permits MLDSA44, MLDSA65, MLDSA87 {

    // Ring parameters (constant across all parameter sets)

    /** Prime modulus q = 2^23 - 2^13 + 1 = 8380417 */
    int Q = 8380417;

    /** Polynomial degree n = 256 */
    int N = 256;

    /** Number of bits dropped from t: d = 13 */
    int D = 13;

    /** Seed length in bytes */
    int SEED_BYTES = 32;

    // Variable parameters per security level

    /** Number of rows in matrix A */
    int k();

    /** Number of columns in matrix A */
    int l();

    /** Secret key coefficient bound */
    int eta();

    /** Number of +/-1 coefficients in challenge polynomial */
    int tau();

    /** y coefficient bound: gamma1 = 2^{17} or 2^{19} */
    int gamma1();

    /** Low-order rounding range for w */
    int gamma2();

    /** Maximum number of hint ones */
    int omega();

    // Derived parameters

    /** Norm bound for z: beta = tau * eta */
    default int beta() {
        return tau() * eta();
    }

    // Key and signature sizes

    /** Public key size in bytes */
    int publicKeyBytes();

    /** Private key size in bytes */
    int privateKeyBytes();

    /** Signature size in bytes */
    int signatureBytes();

    // Encoding bit widths

    /** Bits per coefficient for encoding eta-bounded values */
    default int etaBits() {
        return eta() == 2 ? 3 : 4;
    }

    /** Bits per coefficient for encoding gamma1-bounded values */
    default int gamma1Bits() {
        return gamma1() == (1 << 17) ? 18 : 20;
    }

    /** Log2 of gamma1 */
    default int gamma1Log() {
        return gamma1() == (1 << 17) ? 17 : 19;
    }

    /** Number of bits for encoding t1 */
    default int t1Bits() {
        return 10; // Fixed for all parameter sets: 2^{d-3} = 2^10
    }

    /** Number of bits for encoding t0 */
    default int t0Bits() {
        return 13; // d = 13
    }

    /**
     * Security parameter lambda in bits.
     * ML-DSA-44: 128 bits, ML-DSA-65: 192 bits, ML-DSA-87: 256 bits
     */
    int lambda();

    /**
     * Challenge hash c_tilde length in bytes = lambda / 4.
     */
    default int cTildeBytes() {
        return lambda() / 4;
    }
}
