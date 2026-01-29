package mldsa.poly;

import java.util.Arrays;

/**
 * A vector of polynomials, used for secret keys and intermediate computations.
 * The vector dimension varies by parameter set (k or l polynomials).
 */
public final class PolynomialVector {

    /** The polynomials in this vector */
    private final Polynomial[] polys;

    /**
     * Creates a zero vector of the given dimension.
     *
     * @param dimension the number of polynomials
     */
    public PolynomialVector(int dimension) {
        this.polys = new Polynomial[dimension];
        for (int i = 0; i < dimension; i++) {
            this.polys[i] = new Polynomial();
        }
    }

    /**
     * Creates a vector from the given polynomials.
     * The array is not copied; the polynomials are used directly.
     *
     * @param polynomials the polynomials to use
     */
    public PolynomialVector(Polynomial[] polynomials) {
        this.polys = polynomials;
    }

    /**
     * Gets the dimension (number of polynomials) of this vector.
     *
     * @return the dimension
     */
    public int dimension() {
        return polys.length;
    }

    /**
     * Gets the polynomial at the specified index.
     *
     * @param i the index
     * @return the polynomial
     */
    public Polynomial get(int i) {
        return polys[i];
    }

    /**
     * Sets the polynomial at the specified index.
     *
     * @param i the index
     * @param p the polynomial to set
     */
    public void set(int i, Polynomial p) {
        polys[i] = p;
    }

    /**
     * Returns the internal array of polynomials.
     *
     * @return the polynomial array (not a copy)
     */
    public Polynomial[] polynomials() {
        return polys;
    }

    /**
     * Creates a deep copy of this vector.
     *
     * @return a new vector with copied polynomials
     */
    public PolynomialVector copy() {
        Polynomial[] copied = new Polynomial[polys.length];
        for (int i = 0; i < polys.length; i++) {
            copied[i] = polys[i].copy();
        }
        return new PolynomialVector(copied);
    }

    /**
     * Checks if all polynomials have coefficients within the bound.
     * Constant-time for each polynomial.
     *
     * @param bound the bound to check against
     * @return true if all polynomials satisfy the norm bound
     */
    public boolean checkNorm(int bound) {
        int exceeded = 0;
        for (Polynomial p : polys) {
            // Constant-time OR accumulation
            exceeded |= p.checkNorm(bound) ? 0 : 1;
        }
        return exceeded == 0;
    }

    /**
     * Securely zeros all polynomial coefficients in this vector.
     * Uses memory fence to prevent compiler optimization from removing the zeroing.
     * Call this method when the vector contains secret material that should be erased.
     */
    public void destroy() {
        for (Polynomial p : polys) {
            p.destroy();
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof PolynomialVector other)) return false;
        return Arrays.equals(this.polys, other.polys);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(polys);
    }
}
