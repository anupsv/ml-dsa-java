package mldsa.api;

import mldsa.ct.ConstantTime;
import mldsa.encode.ByteCodec;
import mldsa.hints.Power2Round;
import mldsa.params.Parameters;
import mldsa.poly.Polynomial;
import mldsa.poly.PolynomialVector;
import mldsa.poly.PolyOps;
import mldsa.sampling.ExpandA;

import java.util.Arrays;

/**
 * ML-DSA private key.
 * Contains the encoded private key bytes and associated parameter set.
 *
 * <p>WARNING: Private keys contain sensitive cryptographic material.
 * Handle with care and securely erase when no longer needed.</p>
 */
public final class MLDSAPrivateKey {

    private final MLDSAParameterSet parameterSet;
    private final byte[] encoded;

    // Lazily computed and cached public key bytes
    private volatile byte[] cachedPublicKey;

    /**
     * Creates a private key with validation.
     *
     * @param parameterSet the parameter set this key was generated for
     * @param encoded the encoded private key bytes
     */
    public MLDSAPrivateKey(MLDSAParameterSet parameterSet, byte[] encoded) {
        if (parameterSet == null) {
            throw new IllegalArgumentException("Parameter set cannot be null");
        }
        if (encoded == null) {
            throw new IllegalArgumentException("Encoded key cannot be null");
        }
        if (encoded.length != parameterSet.getPrivateKeySize()) {
            throw new IllegalArgumentException(
                    "Invalid private key size: expected " + parameterSet.getPrivateKeySize() +
                    ", got " + encoded.length);
        }
        this.parameterSet = parameterSet;
        // Defensive copy
        this.encoded = encoded.clone();
    }

    /**
     * Returns the parameter set for this key.
     *
     * @return the parameter set
     */
    public MLDSAParameterSet parameterSet() {
        return parameterSet;
    }

    /**
     * Returns the encoded key bytes.
     * Note: Returns a defensive copy.
     *
     * @return the encoded key bytes
     */
    public byte[] encoded() {
        return encoded.clone();
    }

    /**
     * Returns the raw encoded bytes without copying.
     * For internal use only.
     *
     * @return the raw encoded bytes
     */
    byte[] encodedInternal() {
        return encoded;
    }

    /**
     * Returns the corresponding public key bytes, computing and caching if necessary.
     * This avoids expensive recomputation when signing multiple messages.
     *
     * @return the public key bytes
     */
    byte[] getPublicKeyBytes() {
        byte[] pk = cachedPublicKey;
        if (pk == null) {
            synchronized (this) {
                pk = cachedPublicKey;
                if (pk == null) {
                    pk = computePublicKey();
                    cachedPublicKey = pk;
                }
            }
        }
        return pk;
    }

    /**
     * Computes the public key from this private key.
     * The public key is: rho || encode(t1)
     * where t1 = HighBits(A * s1 + s2)
     */
    private byte[] computePublicKey() {
        Parameters params = parameterSet.getParameters();

        // Decode private key components
        Object[] skParts = ByteCodec.decodePrivateKey(encoded, params);
        byte[] rho = (byte[]) skParts[0];
        // K (skParts[1]), tr (skParts[2]) not needed
        PolynomialVector s1 = (PolynomialVector) skParts[3];
        PolynomialVector s2 = (PolynomialVector) skParts[4];
        // t0 (skParts[5]) not needed

        // Expand A from rho (already in NTT domain per FIPS 204)
        Polynomial[][] A = ExpandA.expandNTT(params, rho);

        // Transform s1 to NTT domain
        PolynomialVector s1Ntt = s1.copy();
        PolyOps.nttVector(s1Ntt);

        // Compute t = A * s1 (in NTT domain) then inverse NTT
        PolynomialVector t = matrixVectorMultiply(A, s1Ntt, params.k());
        PolyOps.invNttVector(t);

        // Reduce and add s2
        for (Polynomial p : t.polynomials()) {
            PolyOps.reduce(p);
        }
        t = PolyOps.add(t, s2);
        for (Polynomial p : t.polynomials()) {
            PolyOps.reduce(p);
        }

        // Power2Round to get t1 (high bits)
        PolynomialVector[] tParts = Power2Round.round(t);
        PolynomialVector t1 = tParts[0];

        // Encode public key
        return ByteCodec.encodePublicKey(rho, t1, params);
    }

    /**
     * Matrix-vector multiplication in NTT domain.
     */
    private static PolynomialVector matrixVectorMultiply(Polynomial[][] A, PolynomialVector v, int k) {
        Polynomial[] result = new Polynomial[k];
        int l = v.dimension();

        for (int i = 0; i < k; i++) {
            result[i] = new Polynomial();
            for (int j = 0; j < l; j++) {
                Polynomial product = PolyOps.pointwiseMultiply(A[i][j], v.get(j));
                result[i] = PolyOps.add(result[i], product);
            }
        }

        return new PolynomialVector(result);
    }

    /**
     * Securely erases the private key material.
     * After calling this method, the key should not be used.
     *
     * <p>Note: Due to Java's memory model, this may not completely
     * prevent the key material from being recoverable. For maximum
     * security, consider using off-heap memory.</p>
     */
    public void destroy() {
        ConstantTime.zero(encoded);
        byte[] pk = cachedPublicKey;
        if (pk != null) {
            ConstantTime.zero(pk);
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof MLDSAPrivateKey other)) return false;
        return this.parameterSet == other.parameterSet &&
               ConstantTime.arraysEqual(this.encoded, other.encoded);
    }

    @Override
    public int hashCode() {
        return 31 * parameterSet.hashCode() + Arrays.hashCode(encoded);
    }

    @Override
    public String toString() {
        // Don't expose key material in toString
        return "MLDSAPrivateKey[" + parameterSet + "]";
    }
}
