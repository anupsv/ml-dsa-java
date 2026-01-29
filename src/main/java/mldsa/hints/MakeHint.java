package mldsa.hints;

import mldsa.params.Parameters;
import mldsa.poly.Polynomial;
import mldsa.poly.PolynomialVector;

/**
 * MakeHint operation for ML-DSA.
 * Computes hints that indicate when the high bits of z0 and r differ.
 */
public final class MakeHint {

    private MakeHint() {
        // Utility class
    }

    /**
     * Computes hint bit for a single coefficient.
     * Per FIPS 204: MakeHint(z0, r, 2γ2) returns 1 if HighBits(r) ≠ HighBits(r + z0)
     *
     * @param z0 the adjustment value (first argument)
     * @param r the reference value (second argument)
     * @param gamma2 the decomposition parameter
     * @return 1 if hint needed, 0 otherwise
     */
    public static int makeHint(int z0, int r, int gamma2) {
        // HighBits(r) vs HighBits(r + z0 mod q)
        int highR = Decompose.highBits(r, gamma2);
        long sum = ((long) r + z0) % Parameters.Q;
        if (sum < 0) sum += Parameters.Q;
        int highSum = Decompose.highBits((int) sum, gamma2);

        return highR != highSum ? 1 : 0;
    }

    /**
     * Computes hints for an entire polynomial.
     *
     * @param z0 the first polynomial
     * @param z1 the second polynomial
     * @param gamma2 the decomposition parameter
     * @return polynomial with hint bits (0 or 1)
     */
    public static Polynomial makeHint(Polynomial z0, Polynomial z1, int gamma2) {
        int[] coeffsZ0 = z0.coefficients();
        int[] coeffsZ1 = z1.coefficients();
        int[] hints = new int[Parameters.N];

        for (int i = 0; i < Parameters.N; i++) {
            hints[i] = makeHint(coeffsZ0[i], coeffsZ1[i], gamma2);
        }

        return new Polynomial(hints);
    }

    /**
     * Computes hints for a polynomial vector.
     *
     * @param z0 the first vector
     * @param z1 the second vector
     * @param gamma2 the decomposition parameter
     * @return vector with hint polynomials
     */
    public static PolynomialVector makeHint(PolynomialVector z0, PolynomialVector z1, int gamma2) {
        if (z0.dimension() != z1.dimension()) {
            throw new IllegalArgumentException("Vector dimensions must match");
        }

        int dim = z0.dimension();
        Polynomial[] hints = new Polynomial[dim];

        for (int i = 0; i < dim; i++) {
            hints[i] = makeHint(z0.get(i), z1.get(i), gamma2);
        }

        return new PolynomialVector(hints);
    }

    /**
     * Counts the total number of 1s in the hint vector.
     *
     * @param h the hint vector
     * @return the number of hints (number of 1s)
     */
    public static int countHints(PolynomialVector h) {
        int count = 0;
        for (Polynomial p : h.polynomials()) {
            int[] coeffs = p.coefficients();
            for (int c : coeffs) {
                count += c;
            }
        }
        return count;
    }
}
