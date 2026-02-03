/**
 * Polynomial arithmetic in the ring R_q = Z_q[X]/(X^256 + 1).
 *
 * <h2>Overview</h2>
 * <p>ML-DSA performs all operations on polynomials with 256 coefficients
 * in the ring Z_q where q = 8,380,417. This package provides the core
 * polynomial data structures and operations.</p>
 *
 * <h2>Key Classes</h2>
 * <ul>
 *   <li>{@link mldsa.poly.Polynomial} - A single polynomial with 256 integer coefficients</li>
 *   <li>{@link mldsa.poly.PolynomialVector} - A vector of polynomials (dimension k or l)</li>
 *   <li>{@link mldsa.poly.PolyOps} - Static operations: add, subtract, multiply, NTT transforms</li>
 * </ul>
 *
 * <h2>Coefficient Representation</h2>
 * <p>Coefficients are stored as Java {@code int} values in the range [0, q-1] for
 * standard form, or in centered form [-(q-1)/2, (q-1)/2] for norm checking.
 * The {@link mldsa.poly.Polynomial#checkNorm(int)} method uses constant-time
 * centered reduction.</p>
 *
 * <h2>Security Features</h2>
 * <ul>
 *   <li><b>Constant-time norm checking</b> - No early exits based on coefficient values</li>
 *   <li><b>Secure destruction</b> - {@link mldsa.poly.Polynomial#destroy()} zeros coefficients</li>
 *   <li><b>Defensive copying</b> - Constructors copy input arrays</li>
 * </ul>
 *
 * <h2>Performance Notes</h2>
 * <p>Polynomial multiplication is performed in the NTT domain for efficiency.
 * Use {@link mldsa.poly.PolyOps#nttVector(PolynomialVector)} to transform,
 * {@link mldsa.poly.PolyOps#pointwiseMultiply(Polynomial, Polynomial)} for
 * element-wise multiplication, and {@link mldsa.poly.PolyOps#invNttVector(PolynomialVector)}
 * to transform back.</p>
 *
 * @since 1.0
 */
package mldsa.poly;
