package mldsa.sampling;

import mldsa.hash.Shake;
import mldsa.params.Parameters;
import mldsa.poly.Polynomial;

/**
 * Expands the seed rho into the public matrix A using rejection sampling.
 * Each element A[i][j] is sampled by hashing rho || j || i with SHAKE128.
 */
public final class ExpandA {

    private ExpandA() {
        // Utility class
    }

    /**
     * Expands a seed into the k x l matrix A.
     * Each polynomial A[i][j] is generated deterministically from rho || j || i.
     *
     * @param params the parameter set
     * @param rho the 32-byte seed
     * @return the matrix A as a 2D array of polynomials (row-major: A[row][col])
     */
    public static Polynomial[][] expand(Parameters params, byte[] rho) {
        int k = params.k();
        int l = params.l();
        Polynomial[][] matrix = new Polynomial[k][l];

        for (int i = 0; i < k; i++) {
            for (int j = 0; j < l; j++) {
                matrix[i][j] = samplePolynomial(rho, (byte) j, (byte) i);
            }
        }

        return matrix;
    }

<<<<<<< HEAD
    // SHAKE128 rate in bytes (1600 - 2*128) / 8 = 168
    private static final int SHAKE128_RATE = 168;

    /**
     * Samples a single polynomial using rejection sampling from SHAKE128.
     * Coefficients are uniformly distributed in [0, q).
     * Uses streaming XOF to squeeze bytes incrementally as needed.
=======
    /**
     * Samples a single polynomial using rejection sampling from SHAKE128.
     * Coefficients are uniformly distributed in [0, q).
>>>>>>> origin/anupsv/security-review
     *
     * @param rho the 32-byte seed
     * @param j the column index (encoded as single byte)
     * @param i the row index (encoded as single byte)
     * @return a polynomial with uniform coefficients in [0, q)
     */
    private static Polynomial samplePolynomial(byte[] rho, byte j, byte i) {
<<<<<<< HEAD
        // Create streaming XOF: absorb rho || j || i
        Shake.ShakeDigest xof = Shake.newShake128();
        xof.update(rho);
        xof.update(j);
        xof.update(i);

        int[] coeffs = new int[Parameters.N];
        int coeffIndex = 0;

        // Squeeze in blocks to avoid per-byte allocation overhead
        byte[] block = new byte[SHAKE128_RATE];
        int blockIndex = SHAKE128_RATE; // Start past end to trigger first squeeze

        while (coeffIndex < Parameters.N) {
            // Squeeze more bytes if needed (need 3 bytes per sample attempt)
            if (blockIndex + 3 > SHAKE128_RATE) {
                xof.digest(block, 0, SHAKE128_RATE);
                blockIndex = 0;
            }

            // Sample a 24-bit value and reject if >= q
            int b0 = block[blockIndex++] & 0xFF;
            int b1 = block[blockIndex++] & 0xFF;
            int b2 = block[blockIndex++] & 0xFF;
=======
        // Create input: rho || j || i
        byte[] input = new byte[34];
        System.arraycopy(rho, 0, input, 0, 32);
        input[32] = j;
        input[33] = i;

        // Generate enough bytes for rejection sampling
        // Each coefficient needs up to 3 bytes; we may need multiple tries
        // 256 coefficients * 3 bytes * 1.2 (rejection rate) ~ 920 bytes
        // Use 1024 bytes initially, expand if needed
        byte[] stream = Shake.shake128(input, 1024);

        int[] coeffs = new int[Parameters.N];
        int coeffIndex = 0;
        int byteIndex = 0;

        while (coeffIndex < Parameters.N) {
            // Expand stream if needed
            if (byteIndex + 3 > stream.length) {
                byte[] newStream = Shake.shake128(input, stream.length + 512);
                stream = newStream;
            }

            // Sample a 24-bit value and reject if >= q
            int b0 = stream[byteIndex++] & 0xFF;
            int b1 = stream[byteIndex++] & 0xFF;
            int b2 = stream[byteIndex++] & 0xFF;
>>>>>>> origin/anupsv/security-review

            // Combine bytes into 23-bit value (only 23 bits needed for q < 2^23)
            int candidate = b0 | (b1 << 8) | ((b2 & 0x7F) << 16);

            if (candidate < Parameters.Q) {
                coeffs[coeffIndex++] = candidate;
            }
        }

        return new Polynomial(coeffs);
    }

    /**
     * Expands matrix A for use in the NTT domain.
     * In ML-DSA (FIPS 204), A is sampled directly in the NTT domain (RejNTTPoly).
     * This method returns the matrix as-is without applying an additional transform.
     *
     * @param params the parameter set
     * @param rho the 32-byte seed
     * @return the matrix A in NTT domain
     */
    public static Polynomial[][] expandNTT(Parameters params, byte[] rho) {
        return expand(params, rho);
    }
}
