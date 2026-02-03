package mldsa.poly;

import mldsa.ct.ConstantTime;
import mldsa.ntt.Montgomery;
import mldsa.ntt.NTT;
import mldsa.params.Parameters;

/**
 * Polynomial arithmetic operations for ML-DSA.
 * All operations are performed modulo q = 8380417.
 */
public final class PolyOps {

    private PolyOps() {
        // Utility class
    }

    /**
     * Adds two polynomials coefficient-wise: result = a + b mod q.
     * Creates a new polynomial with the result.
     *
     * @param a first polynomial
     * @param b second polynomial
     * @return a + b mod q
     */
    public static Polynomial add(Polynomial a, Polynomial b) {
        Polynomial result = new Polynomial();
        int[] ra = a.coefficients();
        int[] rb = b.coefficients();
        int[] rc = result.coefficients();
        for (int i = 0; i < Parameters.N; i++) {
            rc[i] = Montgomery.add(ra[i], rb[i]);
        }
        return result;
    }

    /**
     * Adds polynomial b to polynomial a in place: a += b mod q.
     *
     * @param a polynomial to modify
     * @param b polynomial to add
     */
    public static void addInPlace(Polynomial a, Polynomial b) {
        int[] ra = a.coefficients();
        int[] rb = b.coefficients();
        for (int i = 0; i < Parameters.N; i++) {
            ra[i] = Montgomery.add(ra[i], rb[i]);
        }
    }

    /**
     * Subtracts two polynomials coefficient-wise: result = a - b mod q.
     * Creates a new polynomial with the result.
     *
     * @param a first polynomial
     * @param b second polynomial
     * @return a - b mod q
     */
    public static Polynomial subtract(Polynomial a, Polynomial b) {
        Polynomial result = new Polynomial();
        int[] ra = a.coefficients();
        int[] rb = b.coefficients();
        int[] rc = result.coefficients();
        for (int i = 0; i < Parameters.N; i++) {
            rc[i] = Montgomery.subtract(ra[i], rb[i]);
        }
        return result;
    }

    /**
     * Subtracts polynomial b from polynomial a in place: a -= b mod q.
     *
     * @param a polynomial to modify
     * @param b polynomial to subtract
     */
    public static void subtractInPlace(Polynomial a, Polynomial b) {
        int[] ra = a.coefficients();
        int[] rb = b.coefficients();
        for (int i = 0; i < Parameters.N; i++) {
            ra[i] = Montgomery.subtract(ra[i], rb[i]);
        }
    }

    /**
     * Negates a polynomial: result = -a mod q.
     * Constant-time implementation using branchless arithmetic.
     *
     * @param a the polynomial to negate
     * @return -a mod q
     */
    public static Polynomial negate(Polynomial a) {
        Polynomial result = new Polynomial();
        int[] ra = a.coefficients();
        int[] rc = result.coefficients();
        for (int i = 0; i < Parameters.N; i++) {
            // Branchless: Q - a[i], but keep 0 as 0
            int neg = Parameters.Q - ra[i];
            int isZero = ConstantTime.equals(ra[i], 0);  // -1 if zero, 0 otherwise
            rc[i] = ConstantTime.select(isZero, 0, neg);
        }
        return result;
    }

    /**
     * Pointwise multiplication of two polynomials in NTT domain.
     * Both inputs must already be in NTT representation.
     * The result coefficients are in Montgomery form.
     *
     * @param a first polynomial in NTT domain (Montgomery form)
     * @param b second polynomial in NTT domain (Montgomery form)
     * @return pointwise product in NTT domain
     */
    public static Polynomial pointwiseMultiply(Polynomial a, Polynomial b) {
        Polynomial result = new Polynomial();
        int[] ra = a.coefficients();
        int[] rb = b.coefficients();
        int[] rc = result.coefficients();
        for (int i = 0; i < Parameters.N; i++) {
            rc[i] = Montgomery.multiply(ra[i], rb[i]);
        }
        return result;
    }

    /**
     * Pointwise multiplication and accumulation: acc += a * b.
     * All polynomials must be in NTT domain.
     *
     * @param acc accumulator polynomial (modified in place)
     * @param a first factor
     * @param b second factor
     */
    public static void pointwiseMultiplyAccumulate(Polynomial acc, Polynomial a, Polynomial b) {
        int[] racc = acc.coefficients();
        int[] ra = a.coefficients();
        int[] rb = b.coefficients();
        for (int i = 0; i < Parameters.N; i++) {
            int product = Montgomery.multiply(ra[i], rb[i]);
            racc[i] = Montgomery.add(racc[i], product);
        }
    }

    /**
     * Multiplies two polynomials using NTT.
     * Computes a * b in R_q = Z_q[X]/(X^n + 1).
<<<<<<< HEAD
     * Temporary NTT copies are securely zeroed after use.
=======
>>>>>>> origin/anupsv/security-review
     *
     * @param a first polynomial (standard form)
     * @param b second polynomial (standard form)
     * @return a * b mod (X^n + 1) mod q
     */
    public static Polynomial multiply(Polynomial a, Polynomial b) {
        // Transform both to NTT domain
        Polynomial aNtt = a.copy();
        Polynomial bNtt = b.copy();
<<<<<<< HEAD
        try {
            NTT.forward(aNtt);
            NTT.forward(bNtt);

            // Pointwise multiply
            Polynomial result = pointwiseMultiply(aNtt, bNtt);

            // Transform back
            NTT.inverse(result);

            return result;
        } finally {
            // Zero temporary NTT copies to prevent secret leakage
            aNtt.destroy();
            bNtt.destroy();
        }
=======
        NTT.forward(aNtt);
        NTT.forward(bNtt);

        // Pointwise multiply
        Polynomial result = pointwiseMultiply(aNtt, bNtt);

        // Transform back
        NTT.inverse(result);

        return result;
>>>>>>> origin/anupsv/security-review
    }

    /**
     * Reduces all coefficients to [0, q).
     * Used after operations that may produce values outside this range.
     *
     * @param p the polynomial to reduce (modified in place)
     */
    public static void reduce(Polynomial p) {
        int[] coeffs = p.coefficients();
        for (int i = 0; i < Parameters.N; i++) {
            coeffs[i] = Montgomery.reduce32(coeffs[i]);
        }
    }

    /**
     * Shifts polynomial coefficients left by d bits: result = p * 2^d mod q.
     *
     * @param p the polynomial
     * @param d the number of bits to shift
     * @return p * 2^d mod q
     */
    public static Polynomial shiftLeft(Polynomial p, int d) {
        Polynomial result = new Polynomial();
        int[] rp = p.coefficients();
        int[] rc = result.coefficients();
        for (int i = 0; i < Parameters.N; i++) {
            long shifted = ((long) rp[i]) << d;
            rc[i] = (int) (shifted % Parameters.Q);
        }
        return result;
    }

    // ==================== Vector Operations ====================

    /**
     * Adds two polynomial vectors: result = a + b.
     *
     * @param a first vector
     * @param b second vector
     * @return a + b (component-wise polynomial addition)
     */
    public static PolynomialVector add(PolynomialVector a, PolynomialVector b) {
        if (a.dimension() != b.dimension()) {
            throw new IllegalArgumentException("Vector dimensions must match");
        }
        Polynomial[] result = new Polynomial[a.dimension()];
        for (int i = 0; i < a.dimension(); i++) {
            result[i] = add(a.get(i), b.get(i));
        }
        return new PolynomialVector(result);
    }

    /**
     * Subtracts two polynomial vectors: result = a - b.
     *
     * @param a first vector
     * @param b second vector
     * @return a - b (component-wise polynomial subtraction)
     */
    public static PolynomialVector subtract(PolynomialVector a, PolynomialVector b) {
        if (a.dimension() != b.dimension()) {
            throw new IllegalArgumentException("Vector dimensions must match");
        }
        Polynomial[] result = new Polynomial[a.dimension()];
        for (int i = 0; i < a.dimension(); i++) {
            result[i] = subtract(a.get(i), b.get(i));
        }
        return new PolynomialVector(result);
    }

    /**
     * Applies NTT to each polynomial in the vector.
     *
     * @param v the vector (modified in place)
     */
    public static void nttVector(PolynomialVector v) {
        for (Polynomial p : v.polynomials()) {
            NTT.forward(p);
        }
    }

    /**
     * Applies inverse NTT to each polynomial in the vector.
     *
     * @param v the vector (modified in place)
     */
    public static void invNttVector(PolynomialVector v) {
        for (Polynomial p : v.polynomials()) {
            NTT.inverse(p);
        }
    }

    /**
<<<<<<< HEAD
     * Reduces all coefficients in each polynomial to [0, q).
     * Used after operations that may produce values outside this range.
     *
     * @param v the vector (modified in place)
     */
    public static void reduceVector(PolynomialVector v) {
        for (Polynomial p : v.polynomials()) {
            reduce(p);
        }
    }

    /**
=======
>>>>>>> origin/anupsv/security-review
     * Inner product of two polynomial vectors in NTT domain.
     * Returns sum of pointwise products: result = sum(a[i] * b[i]).
     *
     * @param a first vector (in NTT domain)
     * @param b second vector (in NTT domain)
     * @return inner product polynomial (in NTT domain)
     */
    public static Polynomial innerProduct(PolynomialVector a, PolynomialVector b) {
        if (a.dimension() != b.dimension()) {
            throw new IllegalArgumentException("Vector dimensions must match");
        }
        Polynomial result = new Polynomial();
        for (int i = 0; i < a.dimension(); i++) {
            pointwiseMultiplyAccumulate(result, a.get(i), b.get(i));
        }
        return result;
    }
}
