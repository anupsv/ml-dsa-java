package mldsa;

import mldsa.api.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

/**
 * NIST Known Answer Tests (KAT) for ML-DSA FIPS 204.
 * Test vectors from: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
 */
class NISTKATTests {

    private static final HexFormat HEX = HexFormat.of().withUpperCase();

    // ==================== ML-DSA-44 KeyGen Tests ====================

    @Test
    @DisplayName("NIST KAT: ML-DSA-44 KeyGen tcId=1")
    void testKeyGen44_tcId1() {
        byte[] seed = HEX.parseHex("D71361C000F9A7BC99DFB425BCB6BB27C32C36AB444FF3708B2D93B4E66D5B5B");

        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_44, seed);

        String expectedPkPrefix = "B845FA2881407A59183071629B08223128116014FB58FF6BB4C8C9FE19CF5B0B";
        String actualPkPrefix = HEX.formatHex(keyPair.publicKey().encoded(), 0, 32);
        assertEquals(expectedPkPrefix, actualPkPrefix, "Public key prefix should match NIST KAT");

        String expectedSkPrefix = "B845FA2881407A59183071629B08223128116014FB58FF6BB4C8C9FE19CF5B0B";
        String actualSkPrefix = HEX.formatHex(keyPair.privateKey().encoded(), 0, 32);
        assertEquals(expectedSkPrefix, actualSkPrefix, "Private key prefix should match NIST KAT");
    }

    @Test
    @DisplayName("NIST KAT: ML-DSA-44 KeyGen tcId=2")
    void testKeyGen44_tcId2() {
        byte[] seed = HEX.parseHex("AB611F971C44D1B755D289E0FCFEE70F0EB5D9FDFB1BC31CA894A75794235AF8");

        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_44, seed);

        String expectedPkPrefix = "D712599A161ECD99EF5B7A04313D5507D612565F03AA9695ED7C2DF1CFA18056";
        String actualPkPrefix = HEX.formatHex(keyPair.publicKey().encoded(), 0, 32);
        assertEquals(expectedPkPrefix, actualPkPrefix, "Public key prefix should match NIST KAT");
    }

    @Test
    @DisplayName("NIST KAT: ML-DSA-44 KeyGen tcId=3")
    void testKeyGen44_tcId3() {
        byte[] seed = HEX.parseHex("E0264F45D58EA02C8738C006CAED00F3ED9296E2F6BBF4D158FE71C2983FDF38");

        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_44, seed);

        String expectedPkPrefix = "8A0DDD293EEA646F5A09A0513991CEAF8F5D7D458CF40F7C1F18F6DBA8F4C2F8";
        String actualPkPrefix = HEX.formatHex(keyPair.publicKey().encoded(), 0, 32);
        assertEquals(expectedPkPrefix, actualPkPrefix, "Public key prefix should match NIST KAT");
    }

    // ==================== Key Size Verification ====================

    @Test
    @DisplayName("NIST KAT: ML-DSA-65 Key Sizes")
    void testKeyGen65_sizes() {
        byte[] seed = HEX.parseHex("1BD67DC782B2958E189E315C040DD1F64C8AB232A6A170E1A7A52C33F10851B1");

        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_65, seed);

        assertEquals(1952, keyPair.publicKey().encoded().length, "ML-DSA-65 public key size");
        assertEquals(4032, keyPair.privateKey().encoded().length, "ML-DSA-65 private key size");
    }

    @Test
    @DisplayName("NIST KAT: ML-DSA-87 Key Sizes")
    void testKeyGen87_sizes() {
        byte[] seed = HEX.parseHex("F7052FBB921759CD8716773BA6355630121D6927899FDDA5768E2BC240FCCB7B");

        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_87, seed);

        assertEquals(2592, keyPair.publicKey().encoded().length, "ML-DSA-87 public key size");
        assertEquals(4896, keyPair.privateKey().encoded().length, "ML-DSA-87 private key size");
    }

    // ==================== Deterministic Generation Tests ====================

    @Test
    @DisplayName("NIST KAT: Deterministic key generation")
    void testDeterministicKeyGen() {
        byte[] seed = HEX.parseHex("D71361C000F9A7BC99DFB425BCB6BB27C32C36AB444FF3708B2D93B4E66D5B5B");

        for (MLDSAParameterSet params : MLDSAParameterSet.values()) {
            MLDSAKeyPair kp1 = MLDSA.generateKeyPair(params, seed);
            MLDSAKeyPair kp2 = MLDSA.generateKeyPair(params, seed);

            assertArrayEquals(kp1.publicKey().encoded(), kp2.publicKey().encoded(),
                    "Same seed should produce same PK for " + params);
            assertArrayEquals(kp1.privateKey().encoded(), kp2.privateKey().encoded(),
                    "Same seed should produce same SK for " + params);
        }
    }

    // ==================== Multiple NIST Seeds ====================

    @Test
    @DisplayName("NIST KAT: ML-DSA-44 Multiple Seeds Key Generation")
    void testKeyGen44_multipleSeeds() {
        String[] seeds = {
            "912A7661FE0E8EE0E8340CD82EA2C8679375B9DC8C41109D62100689F4EAA919",
            "885B7DF7CF6695F30AA3F1BC6A3840B8CA3101734118AE619166838AA3EFDBCD",
            "658828B30FFC0D7EADF8CF3E754C0B40B6D9F70F415688B9DE865E0C8C3BD9B8",
            "03834CA530EE44DEE4EBC059283CD8C8154871EFE5FC84A7CF945E4E084BC080",
            "9305119EC76ECA4D7241AB89A182730B4256C60A3731C6BDFFE705E69143F901"
        };

        for (String seedHex : seeds) {
            byte[] seed = HEX.parseHex(seedHex);
            MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_44, seed);

            assertEquals(1312, keyPair.publicKey().encoded().length, "PK size for seed " + seedHex);
            assertEquals(2560, keyPair.privateKey().encoded().length, "SK size for seed " + seedHex);
        }
    }

    @Test
    @DisplayName("NIST KAT: ML-DSA-65 Multiple Seeds Key Generation")
    void testKeyGen65_multipleSeeds() {
        String[] seeds = {
            "455ECBD3C4A9EFB75A302DF08E770BF79E8605DC13ED57D7319AA6BFD1B6496B",
            "DDC3DE6AAA57CCF19272FB4CC76D933D292D11921CA93F4AB3DBE18AFD9A5DF0",
            "CA464DD4C09BA7346057527285D84AAC437DB1525EF72403D93D8E0E9301E9A0",
            "684201C617E77778DBC6F0634E336C275C27401248440E2B0D01846746FB1CD0",
            "2DFC84C9589EA2C45124288B86CDE151797FA6F0C94EB762501381E9CEF707C3"
        };

        for (String seedHex : seeds) {
            byte[] seed = HEX.parseHex(seedHex);
            MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_65, seed);

            assertEquals(1952, keyPair.publicKey().encoded().length, "PK size for seed " + seedHex);
            assertEquals(4032, keyPair.privateKey().encoded().length, "SK size for seed " + seedHex);
        }
    }

    @Test
    @DisplayName("NIST KAT: ML-DSA-87 Multiple Seeds Key Generation")
    void testKeyGen87_multipleSeeds() {
        String[] seeds = {
            "A3818AA042DE46A879494665E551876C1CCF81B6A3D6D1E6B12B21D9BA5D4AC3",
            "5C10E8429211E4017CF3CCC7EF4238BA1EBCD58A8A05E0BDF2F973D3F9A10415",
            "76BBFC13697275B40330A1FB348CFAEA81CEFAF9E9A52D34493E5AE2A98D6879",
            "55729688CED77B35CAB4C926674679176EC77162CE327830F117B9E8E17659E1",
            "E3F4250B39E0B3660968335BAC483BCC809969054004CFCA3E2FAF19C2A3B647"
        };

        for (String seedHex : seeds) {
            byte[] seed = HEX.parseHex(seedHex);
            MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_87, seed);

            assertEquals(2592, keyPair.publicKey().encoded().length, "PK size for seed " + seedHex);
            assertEquals(4896, keyPair.privateKey().encoded().length, "SK size for seed " + seedHex);
        }
    }

    // ==================== FIPS 204 Size Validation ====================

    @Test
    @DisplayName("NIST FIPS 204: Key and signature sizes match specification")
    void testFIPS204Sizes() {
        // ML-DSA-44 (Table 2 from FIPS 204)
        assertEquals(1312, MLDSAParameterSet.ML_DSA_44.getPublicKeySize());
        assertEquals(2560, MLDSAParameterSet.ML_DSA_44.getPrivateKeySize());
        assertEquals(2420, MLDSAParameterSet.ML_DSA_44.getSignatureSize());

        // ML-DSA-65
        assertEquals(1952, MLDSAParameterSet.ML_DSA_65.getPublicKeySize());
        assertEquals(4032, MLDSAParameterSet.ML_DSA_65.getPrivateKeySize());
        assertEquals(3309, MLDSAParameterSet.ML_DSA_65.getSignatureSize());

        // ML-DSA-87
        assertEquals(2592, MLDSAParameterSet.ML_DSA_87.getPublicKeySize());
        assertEquals(4896, MLDSAParameterSet.ML_DSA_87.getPrivateKeySize());
        assertEquals(4627, MLDSAParameterSet.ML_DSA_87.getSignatureSize());
    }

}
