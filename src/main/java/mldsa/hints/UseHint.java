package mldsa.hints;

import mldsa.ct.ConstantTime;
import mldsa.params.Parameters;
import mldsa.poly.Polynomial;
import mldsa.poly.PolynomialVector;

/**
 * UseHint operation for ML-DSA.
 * Recovers the high bits of a value using the stored hint.
 * Implemented in constant-time to prevent timing side-channels.
 */
public final class UseHint {

    private UseHint() {
        // Utility class
    }

    /**
     * Uses a hint to recover the correct high bits.
     * Constant-time implementation using branchless arithmetic.
     *
     * @param hint the hint bit (0 or 1)
     * @param r the value whose high bits to recover
     * @param gamma2 the decomposition parameter
     * @return the correct high bits
     */
    public static int useHint(int hint, int r, int gamma2) {
        int[] parts = Decompose.decompose(r, gamma2);
        int r1 = parts[0];
        int r0 = parts[1];

        int m = (Parameters.Q - 1) / (2 * gamma2);

        // Compute both possible adjustments
        int r1Plus = (r1 + 1) % m;      // Used when hint=1 and r0 > 0
        int r1Minus = (r1 - 1 + m) % m; // Used when hint=1 and r0 <= 0

        // Branchless selection based on r0 sign
        // r0Positive is -1 if r0 > 0, else 0
        int r0Positive = ConstantTime.greaterThan(r0, 0);
        int adjusted = ConstantTime.select(r0Positive, r1Plus, r1Minus);

        // Branchless selection based on hint
        // hintMask is -1 if hint != 0, else 0
        int hintMask = ConstantTime.notEquals(hint, 0);
        return ConstantTime.select(hintMask, adjusted, r1);
    }

    /**
     * Uses hints to recover high bits for a polynomial.
     *
     * @param hints the hint polynomial (coefficients are 0 or 1)
     * @param r the polynomial
     * @param gamma2 the decomposition parameter
     * @return polynomial of recovered high bits
     */
    public static Polynomial useHint(Polynomial hints, Polynomial r, int gamma2) {
        int[] hintCoeffs = hints.coefficients();
        int[] rCoeffs = r.coefficients();
        int[] result = new int[Parameters.N];

        for (int i = 0; i < Parameters.N; i++) {
            result[i] = useHint(hintCoeffs[i], rCoeffs[i], gamma2);
        }

        return new Polynomial(result);
    }

    /**
     * Uses hints to recover high bits for a polynomial vector.
     *
     * @param hints the hint vector
     * @param r the polynomial vector
     * @param gamma2 the decomposition parameter
     * @return vector of recovered high bits polynomials
     */
    public static PolynomialVector useHint(PolynomialVector hints, PolynomialVector r, int gamma2) {
        if (hints.dimension() != r.dimension()) {
            throw new IllegalArgumentException("Vector dimensions must match");
        }

        int dim = hints.dimension();
        Polynomial[] result = new Polynomial[dim];

        for (int i = 0; i < dim; i++) {
            result[i] = useHint(hints.get(i), r.get(i), gamma2);
        }

        return new PolynomialVector(result);
    }
}
