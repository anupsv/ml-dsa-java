package mldsa.core;

import mldsa.ct.ConstantTime;
import mldsa.encode.BitPacker;
import mldsa.encode.ByteCodec;
import mldsa.hash.Shake;
import mldsa.hints.Decompose;
import mldsa.hints.MakeHint;
import mldsa.ntt.NTT;
import mldsa.params.Parameters;
import mldsa.poly.Polynomial;
import mldsa.poly.PolyOps;
import mldsa.poly.PolynomialVector;
import mldsa.ct.SecureRandomHolder;
import mldsa.sampling.ExpandA;
import mldsa.sampling.Sampler;

/**
 * ML-DSA Signing (Algorithm 2 in FIPS 204).
 * Implements the Fiat-Shamir with Aborts paradigm for lattice-based signatures.
 */
public final class Sign {

    private Sign() {
        // Utility class
    }

    /** Maximum number of signing iterations before giving up */
    private static final int MAX_ITERATIONS = 1000;

    /**
     * Signs a message using the private key.
     *
     * @param params the parameter set
     * @param privateKey the encoded private key
     * @param message the message to sign
     * @return the encoded signature
     */
    public static byte[] sign(Parameters params, byte[] privateKey, byte[] message) {
        // Generate random bytes for hedged signing
        byte[] rnd = new byte[32];
        SecureRandomHolder.nextBytes(rnd);
        return sign(params, privateKey, message, rnd);
    }

    /**
     * Signs a message with a specific random value (for deterministic testing).
     *
     * @param params the parameter set
     * @param privateKey the encoded private key
     * @param message the message to sign
     * @param rnd 32-byte randomness for hedged signing
     * @return the encoded signature
     */
    public static byte[] sign(Parameters params, byte[] privateKey, byte[] message, byte[] rnd) {
        int k = params.k();
        int l = params.l();
        int gamma1 = params.gamma1();
        int gamma2 = params.gamma2();
        int beta = params.beta();
        int omega = params.omega();

        // Step 1: Decode private key
        Object[] skParts = ByteCodec.decodePrivateKey(privateKey, params);
        byte[] rho = (byte[]) skParts[0];
        byte[] K = (byte[]) skParts[1];
        byte[] tr = (byte[]) skParts[2];
        PolynomialVector s1 = (PolynomialVector) skParts[3];
        PolynomialVector s2 = (PolynomialVector) skParts[4];
        PolynomialVector t0 = (PolynomialVector) skParts[5];

        // Step 2: Expand A from rho (in NTT domain)
        Polynomial[][] A = ExpandA.expandNTT(params, rho);

        // Step 3: Transform s1, s2, t0 to NTT domain for efficient multiplication
        PolynomialVector s1Ntt = s1.copy();
        PolynomialVector s2Ntt = s2.copy();
        PolynomialVector t0Ntt = t0.copy();
        PolyOps.nttVector(s1Ntt);
        PolyOps.nttVector(s2Ntt);
        PolyOps.nttVector(t0Ntt);

        // Step 4: Compute mu = H(tr || M)
        byte[] mu = Shake.shake256(64, tr, message);

        // Step 5: Compute rhoPrime = H(K || rnd || mu) for mask sampling
        byte[] rhoPrime = Shake.shake256(64, K, rnd, mu);

        byte[] signature = null;

        // Track intermediate values for zeroization (last iteration's values)
        PolynomialVector lastY = null;
        PolynomialVector lastYNtt = null;
        PolynomialVector lastCs2 = null;
        PolynomialVector lastCt0 = null;
        PolynomialVector lastZ = null;
        Polynomial lastCNtt = null;

        try {
            // Step 6: Main signing loop (Fiat-Shamir with Aborts)
            int kappa = 0;

            while (kappa < MAX_ITERATIONS) {
                // Zero previous iteration's intermediates before creating new ones
                if (lastY != null) lastY.destroy();
                if (lastYNtt != null) lastYNtt.destroy();
                if (lastCs2 != null) lastCs2.destroy();
                if (lastCt0 != null) lastCt0.destroy();
                if (lastZ != null) lastZ.destroy();
                if (lastCNtt != null) lastCNtt.destroy();

                // Step 6a: Sample masking vector y
                PolynomialVector y = Sampler.sampleMask(params, rhoPrime, kappa * l);
                lastY = y;

                // Step 6b: Compute w = A * NTT(y)
                PolynomialVector yNtt = y.copy();
                lastYNtt = yNtt;
                PolyOps.nttVector(yNtt);
                PolynomialVector w = KeyGen.matrixVectorMultiply(A, yNtt, k);
                PolyOps.invNttVector(w);
                PolyOps.reduceVector(w);  // Reduce to [0, Q) after inverse NTT

                // Step 6c: Decompose w into w1 (high bits) and w0 (low bits)
                PolynomialVector w1 = Decompose.highBits(w, gamma2);

                // Step 6d: Compute challenge hash c_tilde = H(mu || w1_encoded)
                // c_tilde length is lambda/4 bytes per FIPS 204
                byte[] w1Encoded = BitPacker.encodeW1(w1, params);
                byte[] cTilde = Shake.shake256(params.cTildeBytes(), mu, w1Encoded);

                // Step 6e: Sample challenge polynomial c from c_tilde
                Polynomial c = Sampler.sampleInBall(params, cTilde);

                // Step 6f: Compute z = y + c * s1
                Polynomial cNtt = c.copy();
                lastCNtt = cNtt;
                NTT.forward(cNtt);

                PolynomialVector z = new PolynomialVector(l);
                lastZ = z;
                for (int i = 0; i < l; i++) {
                    Polynomial cs1i = PolyOps.pointwiseMultiply(cNtt, s1Ntt.get(i));
                    NTT.inverse(cs1i);
                    PolyOps.reduce(cs1i);  // Reduce to [0, Q) after inverse NTT
                    Polynomial zi = PolyOps.add(y.get(i), cs1i);
                    PolyOps.reduce(zi);  // Reduce sum to [0, Q) for norm check
                    z.set(i, zi);
                    cs1i.destroy();  // Zero immediately after use
                }

                // Step 6g: Compute r0 = LowBits(w - c * s2)
                PolynomialVector cs2 = new PolynomialVector(k);
                lastCs2 = cs2;
                for (int i = 0; i < k; i++) {
                    Polynomial cs2i = PolyOps.pointwiseMultiply(cNtt, s2Ntt.get(i));
                    NTT.inverse(cs2i);
                    PolyOps.reduce(cs2i);  // Reduce to [0, Q) after inverse NTT
                    cs2.set(i, cs2i);
                }
                PolynomialVector wMinusCs2 = PolyOps.subtract(w, cs2);
                PolyOps.reduceVector(wMinusCs2);  // Reduce to [0, Q) for decomposition
                PolynomialVector r0 = Decompose.lowBits(wMinusCs2, gamma2);

                // Step 6h: Check rejection conditions

                // Condition 1: ||z||_inf >= gamma1 - beta
                if (!z.checkNorm(gamma1 - beta - 1)) {
                    kappa++;
                    continue;
                }

                // Condition 2: ||r0||_inf >= gamma2 - beta
                if (!checkLowBitsNorm(r0, gamma2 - beta - 1)) {
                    kappa++;
                    continue;
                }

                // Step 6i: Compute ct0 = c * t0
                PolynomialVector ct0 = new PolynomialVector(k);
                lastCt0 = ct0;
                for (int i = 0; i < k; i++) {
                    Polynomial ct0i = PolyOps.pointwiseMultiply(cNtt, t0Ntt.get(i));
                    NTT.inverse(ct0i);
                    PolyOps.reduce(ct0i);  // Reduce to [0, Q) after inverse NTT
                    ct0.set(i, ct0i);
                }

                // Step 6j: Compute hints h = MakeHint(-ct0, w - cs2 + ct0)
                PolynomialVector negCt0 = negate(ct0);
                PolynomialVector wMinusCs2PlusCt0 = PolyOps.add(wMinusCs2, ct0);
                PolyOps.reduceVector(wMinusCs2PlusCt0);  // Reduce for MakeHint
                PolynomialVector h = MakeHint.makeHint(negCt0, wMinusCs2PlusCt0, gamma2);

                // Step 6k: Check hint count
                int hintCount = MakeHint.countHints(h);
                if (hintCount > omega) {
                    kappa++;
                    continue;
                }

                // Condition 3: ||ct0||_inf >= gamma2
                if (!ct0.checkNorm(gamma2 - 1)) {
                    kappa++;
                    continue;
                }

                // Step 7: Encode signature (store for return after cleanup)
                signature = ByteCodec.encodeSignature(cTilde, z, h, params);
                break;
            }

            if (signature == null) {
                // Generic error message to avoid leaking rejection statistics
                throw new RuntimeException("Signing failed: maximum iterations exceeded");
            }

            return signature;
        } finally {
            // Zero all secret intermediate values (best-effort given Java GC)
            ConstantTime.zero(K);
            ConstantTime.zero(rhoPrime);
            s1.destroy();
            s2.destroy();
            t0.destroy();
            s1Ntt.destroy();
            s2Ntt.destroy();
            t0Ntt.destroy();

            // Zero loop intermediates
            if (lastY != null) lastY.destroy();
            if (lastYNtt != null) lastYNtt.destroy();
            if (lastCs2 != null) lastCs2.destroy();
            if (lastCt0 != null) lastCt0.destroy();
            if (lastZ != null) lastZ.destroy();
            if (lastCNtt != null) lastCNtt.destroy();
        }
    }

    /**
     * Checks if low bits are within the bound.
     * Low bits are centered, so we check |r0| <= bound.
     * Constant-time implementation using branchless arithmetic to prevent timing leaks.
     */
    private static boolean checkLowBitsNorm(PolynomialVector r0, int bound) {
        int exceeded = 0;
        int halfQ = Parameters.Q / 2;
        for (Polynomial p : r0.polynomials()) {
            int[] coeffs = p.coefficients();
            for (int c : coeffs) {
                // Branchless center reduction
                int overHalf = (halfQ - c) >> 31;  // -1 if c > halfQ, 0 otherwise
                int centered = c + (overHalf & (-Parameters.Q));

                // Branchless absolute value
                int sign = centered >> 31;  // -1 if negative, 0 otherwise
                int abs = (centered ^ sign) - sign;

                // Accumulate exceeded flag (constant-time)
                exceeded |= (bound - abs) >> 31;
            }
        }
        return exceeded == 0;
    }

    /**
     * Negates a polynomial vector.
     */
    private static PolynomialVector negate(PolynomialVector v) {
        Polynomial[] result = new Polynomial[v.dimension()];
        for (int i = 0; i < v.dimension(); i++) {
            result[i] = PolyOps.negate(v.get(i));
        }
        return new PolynomialVector(result);
    }
}
