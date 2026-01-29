package mldsa.hints;

import mldsa.params.Parameters;
import mldsa.poly.Polynomial;
import mldsa.poly.PolynomialVector;

/**
 * Decompose operation for ML-DSA.
 * Decomposes coefficients into high and low parts for signature generation.
 *
 * <p>For coefficient r, computes (r0, r1) where:
 * - r1 is the "high-order" representative
 * - r0 is in [-gamma2, gamma2] except at the special wraparound</p>
 *
 * <p>All operations are constant-time to prevent timing attacks.</p>
 */
public final class Decompose {

    private Decompose() {
        // Utility class
    }

    /**
     * Decomposes a coefficient into high and low parts.
     * Constant-time implementation.
     *
     * @param r the coefficient in [0, q)
     * @param gamma2 the decomposition parameter
     * @return array [r1, r0] where r1 is high bits and r0 is low bits
     */
    public static int[] decompose(int r, int gamma2) {
        // r1 = ceil(r / (2 * gamma2))
        // r0 = r mod +/- (2 * gamma2)

        int twoGamma2 = 2 * gamma2;

        // Compute r1 = (r + gamma2) / (2 * gamma2) (rounding)
        int r1 = (r + gamma2) / twoGamma2;

        // Compute r0 = r - r1 * 2 * gamma2
        int r0 = r - r1 * twoGamma2;

        // Handle the special case when r1 would equal (q-1)/(2*gamma2)
        // In this case, we set r1 = 0 and r0 = r0 - 1 (which wraps)
        int maxR1 = (Parameters.Q - 1) / twoGamma2;

        // Constant-time: if r1 == maxR1, set r1 = 0 and r0 -= 1
        int eq = constantTimeEquals(r1, maxR1);
        r1 = r1 & ~eq; // r1 = 0 if eq, else r1
        r0 = r0 - eq; // r0 -= 1 if eq

        return new int[] { r1, r0 };
    }

    /**
     * Decomposes a polynomial into high and low parts.
     *
     * @param poly the input polynomial
     * @param gamma2 the decomposition parameter
     * @return array [poly_high, poly_low]
     */
    public static Polynomial[] decompose(Polynomial poly, int gamma2) {
        int[] coeffs = poly.coefficients();
        int[] high = new int[Parameters.N];
        int[] low = new int[Parameters.N];

        for (int i = 0; i < Parameters.N; i++) {
            int[] result = decompose(coeffs[i], gamma2);
            high[i] = result[0];
            // Convert r0 to [0, q) representation
            low[i] = result[1] < 0 ? result[1] + Parameters.Q : result[1];
        }

        return new Polynomial[] { new Polynomial(high), new Polynomial(low) };
    }

    /**
     * Decomposes a polynomial vector into high and low parts.
     *
     * @param vec the input vector
     * @param gamma2 the decomposition parameter
     * @return array [vec_high, vec_low]
     */
    public static PolynomialVector[] decompose(PolynomialVector vec, int gamma2) {
        int dim = vec.dimension();
        Polynomial[] high = new Polynomial[dim];
        Polynomial[] low = new Polynomial[dim];

        for (int i = 0; i < dim; i++) {
            Polynomial[] parts = decompose(vec.get(i), gamma2);
            high[i] = parts[0];
            low[i] = parts[1];
        }

        return new PolynomialVector[] {
            new PolynomialVector(high),
            new PolynomialVector(low)
        };
    }

    /**
     * Computes the high bits of a coefficient using a specific gamma2.
     *
     * @param r the coefficient in [0, q)
     * @param gamma2 the decomposition parameter
     * @return the high bits r1
     */
    public static int highBits(int r, int gamma2) {
        return decompose(r, gamma2)[0];
    }

    /**
     * Computes the low bits of a coefficient using a specific gamma2.
     *
     * @param r the coefficient in [0, q)
     * @param gamma2 the decomposition parameter
     * @return the low bits r0 (centered, may be negative)
     */
    public static int lowBits(int r, int gamma2) {
        return decompose(r, gamma2)[1];
    }

    /**
     * Computes high bits for an entire polynomial.
     *
     * @param poly the input polynomial
     * @param gamma2 the decomposition parameter
     * @return polynomial of high bits
     */
    public static Polynomial highBits(Polynomial poly, int gamma2) {
        return decompose(poly, gamma2)[0];
    }

    /**
     * Computes high bits for a polynomial vector.
     *
     * @param vec the input vector
     * @param gamma2 the decomposition parameter
     * @return vector of high bits polynomials
     */
    public static PolynomialVector highBits(PolynomialVector vec, int gamma2) {
        return decompose(vec, gamma2)[0];
    }

    /**
     * Computes low bits for an entire polynomial.
     *
     * @param poly the input polynomial
     * @param gamma2 the decomposition parameter
     * @return polynomial of low bits (in [0, q) representation)
     */
    public static Polynomial lowBits(Polynomial poly, int gamma2) {
        return decompose(poly, gamma2)[1];
    }

    /**
     * Computes low bits for a polynomial vector.
     *
     * @param vec the input vector
     * @param gamma2 the decomposition parameter
     * @return vector of low bits polynomials
     */
    public static PolynomialVector lowBits(PolynomialVector vec, int gamma2) {
        return decompose(vec, gamma2)[1];
    }

    /**
     * Constant-time equality check.
     * Returns -1 (all 1s) if a == b, 0 otherwise.
     */
    private static int constantTimeEquals(int a, int b) {
        int diff = a ^ b;
        // If diff == 0, then (diff - 1) >> 31 gives -1
        // Otherwise it gives 0
        return (((diff - 1) & ~diff) >> 31);
    }
}
