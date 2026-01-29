package mldsa.hints;

import mldsa.params.Parameters;
import mldsa.poly.Polynomial;
import mldsa.poly.PolynomialVector;

/**
 * Power2Round operation for ML-DSA.
 * Rounds coefficients to their high-order bits, used in key generation.
 *
 * <p>For a coefficient r in [0, q), computes (r0, r1) where:
 * - r1 = (r + 2^{d-1}) >> d (high bits)
 * - r0 = r - r1 * 2^d (low bits)
 * with r0 in [-2^{d-1}, 2^{d-1}]</p>
 */
public final class Power2Round {

    private Power2Round() {
        // Utility class
    }

    /** d = 13 for ML-DSA */
    private static final int D = Parameters.D;

    /** 2^d = 8192 */
    private static final int TWO_D = 1 << D;

    /** 2^{d-1} = 4096 */
    private static final int HALF_D = 1 << (D - 1);

    /**
     * Computes Power2Round for a single coefficient.
     *
     * @param r the coefficient in [0, q)
     * @return array [r1, r0] where r1 is high bits and r0 is low bits
     */
    public static int[] round(int r) {
        // r1 = (r + 2^{d-1}) >> d
        int r1 = (r + HALF_D) >> D;

        // r0 = r - r1 * 2^d (will be in [-2^{d-1}+1, 2^{d-1}])
        int r0 = r - (r1 << D);

        return new int[] { r1, r0 };
    }

    /**
     * Computes Power2Round for an entire polynomial.
     *
     * @param poly the input polynomial
     * @return array [poly_high, poly_low] with high and low parts
     */
    public static Polynomial[] round(Polynomial poly) {
        int[] coeffs = poly.coefficients();
        int[] high = new int[Parameters.N];
        int[] low = new int[Parameters.N];

        for (int i = 0; i < Parameters.N; i++) {
            int[] result = round(coeffs[i]);
            high[i] = result[0];
            // Convert low bits to [0, q) representation if negative
            low[i] = result[1] < 0 ? result[1] + Parameters.Q : result[1];
        }

        return new Polynomial[] { new Polynomial(high), new Polynomial(low) };
    }

    /**
     * Computes Power2Round for a polynomial vector.
     *
     * @param vec the input vector
     * @return array [vec_high, vec_low] with high and low parts
     */
    public static PolynomialVector[] round(PolynomialVector vec) {
        int dim = vec.dimension();
        Polynomial[] high = new Polynomial[dim];
        Polynomial[] low = new Polynomial[dim];

        for (int i = 0; i < dim; i++) {
            Polynomial[] parts = round(vec.get(i));
            high[i] = parts[0];
            low[i] = parts[1];
        }

        return new PolynomialVector[] {
            new PolynomialVector(high),
            new PolynomialVector(low)
        };
    }

    /**
     * Reconstructs the original value from high and low parts.
     * r = r1 * 2^d + r0
     *
     * @param r1 high bits
     * @param r0 low bits (may be negative in centered form)
     * @return the original coefficient in [0, q)
     */
    public static int reconstruct(int r1, int r0) {
        // r0 is stored in [0, q), need to interpret as centered
        int centered = r0 > Parameters.Q / 2 ? r0 - Parameters.Q : r0;
        int r = (r1 << D) + centered;
        return r < 0 ? r + Parameters.Q : (r >= Parameters.Q ? r - Parameters.Q : r);
    }
}
