/**
 * Random sampling operations for ML-DSA.
 *
 * <h2>Overview</h2>
 * <p>This package implements the sampling algorithms from FIPS 204 that generate
 * random polynomials and matrices from seeds using SHAKE256.</p>
 *
 * <h2>Key Classes</h2>
 * <ul>
 *   <li>{@link mldsa.sampling.Sampler} - Bounded coefficient and challenge sampling</li>
 *   <li>{@link mldsa.sampling.ExpandA} - Matrix A expansion from seed rho</li>
 * </ul>
 *
 * <h2>Sampling Operations</h2>
 *
 * <h3>Bounded Coefficient Sampling (ExpandS)</h3>
 * <p>Samples secret vectors s1, s2 with coefficients in [-eta, eta] using rejection
 * sampling. For ML-DSA-44, eta=2; for ML-DSA-65/87, eta=4.</p>
 *
 * <h3>Mask Sampling (ExpandMask)</h3>
 * <p>Samples masking vector y with coefficients in [-(gamma1-1), gamma1].
 * gamma1 = 2^17 for ML-DSA-44, 2^19 for ML-DSA-65/87.</p>
 *
 * <h3>Challenge Sampling (SampleInBall)</h3>
 * <p>Generates the challenge polynomial c with exactly tau coefficients being +/- 1
 * and the rest being 0. Uses rejection sampling to ensure uniform distribution.</p>
 *
 * <h3>Matrix Expansion (ExpandA)</h3>
 * <p>Expands the seed rho into the public matrix A using SHAKE128. Each matrix
 * element is sampled independently with coefficients uniformly in [0, q-1].</p>
 *
 * <h2>Security Notes</h2>
 * <ul>
 *   <li>All sampling uses SHAKE256/SHAKE128 as the underlying XOF</li>
 *   <li>Intermediate buffers containing derived secrets are securely cleared</li>
 *   <li>Rejection sampling is used to ensure uniform distribution</li>
 * </ul>
 *
 * @since 1.0
 */
package mldsa.sampling;
