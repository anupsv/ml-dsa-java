/**
 * ML-DSA parameter set definitions.
 *
 * <h2>Overview</h2>
 * <p>This package defines the three ML-DSA parameter sets from FIPS 204, each
 * providing different security levels and performance characteristics.</p>
 *
 * <h2>Key Classes</h2>
 * <ul>
 *   <li>{@link mldsa.params.Parameters} - Interface defining parameter accessors</li>
 *   <li>{@link mldsa.params.MLDSA44} - ML-DSA-44 parameters (Security Level 2)</li>
 *   <li>{@link mldsa.params.MLDSA65} - ML-DSA-65 parameters (Security Level 3)</li>
 *   <li>{@link mldsa.params.MLDSA87} - ML-DSA-87 parameters (Security Level 5)</li>
 * </ul>
 *
 * <h2>Parameter Summary</h2>
 * <table border="1">
 *   <tr><th>Parameter</th><th>ML-DSA-44</th><th>ML-DSA-65</th><th>ML-DSA-87</th></tr>
 *   <tr><td>Security Level</td><td>2</td><td>3</td><td>5</td></tr>
 *   <tr><td>k (rows)</td><td>4</td><td>6</td><td>8</td></tr>
 *   <tr><td>l (columns)</td><td>4</td><td>5</td><td>7</td></tr>
 *   <tr><td>eta</td><td>2</td><td>4</td><td>2</td></tr>
 *   <tr><td>tau</td><td>39</td><td>49</td><td>60</td></tr>
 *   <tr><td>gamma1</td><td>2^17</td><td>2^19</td><td>2^19</td></tr>
 *   <tr><td>gamma2</td><td>(q-1)/88</td><td>(q-1)/32</td><td>(q-1)/32</td></tr>
 *   <tr><td>omega</td><td>80</td><td>55</td><td>75</td></tr>
 *   <tr><td>Public Key</td><td>1,312 B</td><td>1,952 B</td><td>2,592 B</td></tr>
 *   <tr><td>Private Key</td><td>2,560 B</td><td>4,032 B</td><td>4,896 B</td></tr>
 *   <tr><td>Signature</td><td>2,420 B</td><td>3,309 B</td><td>4,627 B</td></tr>
 * </table>
 *
 * <h2>Common Constants</h2>
 * <ul>
 *   <li><b>q = 8,380,417</b>: The prime modulus (2^23 - 2^13 + 1)</li>
 *   <li><b>n = 256</b>: Polynomial degree</li>
 *   <li><b>d = 13</b>: Dropped bits in Power2Round</li>
 * </ul>
 *
 * <h2>Choosing a Parameter Set</h2>
 * <ul>
 *   <li><b>ML-DSA-44</b>: Best performance, suitable for most applications</li>
 *   <li><b>ML-DSA-65</b>: Recommended for sensitive data requiring long-term security</li>
 *   <li><b>ML-DSA-87</b>: Highest security, use for critical infrastructure</li>
 * </ul>
 *
 * @since 1.0
 */
package mldsa.params;
