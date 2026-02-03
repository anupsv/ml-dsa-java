/**
 * Number Theoretic Transform (NTT) for efficient polynomial multiplication.
 *
 * <h2>Overview</h2>
 * <p>This package implements the Number Theoretic Transform, which enables
 * efficient polynomial multiplication in O(n log n) time instead of O(n^2).</p>
 *
 * <h2>Mathematical Background</h2>
 * <p>ML-DSA operates in the polynomial ring R_q = Z_q[X]/(X^256 + 1) where q = 8,380,417.
 * The NTT transforms polynomials into the "NTT domain" where multiplication becomes
 * element-wise, then transforms back.</p>
 *
 * <h2>Key Classes</h2>
 * <ul>
 *   <li>{@link mldsa.ntt.NTT} - Forward and inverse NTT transforms</li>
 *   <li>{@link mldsa.ntt.Montgomery} - Montgomery modular arithmetic</li>
 *   <li>{@link mldsa.ntt.NTTTables} - Precomputed twiddle factors</li>
 * </ul>
 *
 * <h2>Montgomery Arithmetic</h2>
 * <p>Modular reduction is expensive. Montgomery form represents values as a*R mod q
 * where R = 2^32, allowing efficient reduction using only shifts and multiplications.
 * Key constants:</p>
 * <ul>
 *   <li>q = 8,380,417 (the prime modulus)</li>
 *   <li>Q_INV = 58,728,449 (Montgomery constant)</li>
 *   <li>R^2 mod q = 2,365,951 (for conversion to Montgomery form)</li>
 * </ul>
 *
 * <h2>NTT Algorithm</h2>
 * <ul>
 *   <li><b>Forward NTT</b>: Cooley-Tukey decimation-in-time butterfly</li>
 *   <li><b>Inverse NTT</b>: Gentleman-Sande decimation-in-frequency butterfly</li>
 * </ul>
 *
 * @since 1.0
 */
package mldsa.ntt;
