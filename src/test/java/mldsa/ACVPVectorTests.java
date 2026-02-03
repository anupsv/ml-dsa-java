package mldsa;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import mldsa.api.MLDSA;
import mldsa.api.MLDSAKeyPair;
import mldsa.api.MLDSAParameterSet;
import mldsa.api.MLDSAPrivateKey;
import mldsa.api.MLDSASignature;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class ACVPVectorTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();

    @Test
    void acvpKeyGenVectors() throws Exception {
        JsonNode root = readVectors("key-gen.json");
        for (JsonNode group : root.withArray("testGroups")) {
            MLDSAParameterSet params = mapParameterSet(group.get("parameterSet").asText());
            int tgId = group.get("tgId").asInt();
            for (JsonNode test : group.withArray("tests")) {
                int tcId = test.get("tcId").asInt();
                byte[] seed = hexBytes(test.get("seed"));
                byte[] expectedPk = hexBytes(test.get("pk"));
                byte[] expectedSk = hexBytes(test.get("sk"));

                MLDSAKeyPair keyPair = MLDSA.generateKeyPair(params, seed);

                assertArrayEquals(expectedPk, keyPair.publicKey().encoded(),
                        "KeyGen PK mismatch: tgId=" + tgId + " tcId=" + tcId + " params=" + params);
                assertArrayEquals(expectedSk, keyPair.privateKey().encoded(),
                        "KeyGen SK mismatch: tgId=" + tgId + " tcId=" + tcId + " params=" + params);
            }
        }
    }

    @Test
    void acvpSignatureGenerationVectors() throws Exception {
        JsonNode root = readVectors("sig-gen.json");
        for (JsonNode group : root.withArray("testGroups")) {
            MLDSAParameterSet params = mapParameterSet(group.get("parameterSet").asText());
            boolean deterministic = group.get("deterministic").asBoolean();
            int tgId = group.get("tgId").asInt();
            for (JsonNode test : group.withArray("tests")) {
                int tcId = test.get("tcId").asInt();
                byte[] skBytes = hexBytes(test.get("sk"));
                byte[] message = hexBytes(test.get("message"));
                byte[] expectedSignature = hexBytes(test.get("signature"));

                byte[] rnd;
                if (deterministic) {
                    rnd = new byte[32];
                } else {
                    JsonNode rndNode = test.get("rnd");
                    if (rndNode == null || rndNode.isNull() || rndNode.asText().isEmpty()) {
                        fail("Missing rnd for non-deterministic test: tgId=" + tgId + " tcId=" + tcId);
                        return;
                    }
                    rnd = hexBytes(rndNode);
                }

                MLDSAPrivateKey privateKey = new MLDSAPrivateKey(params, skBytes);
                // Use signRaw for ACVP vectors (no domain separation)
                MLDSASignature signature = MLDSA.signRaw(privateKey, message, rnd);

                assertArrayEquals(expectedSignature, signature.encoded(),
                        "SigGen mismatch: tgId=" + tgId + " tcId=" + tcId + " params=" + params);
            }
        }
    }

    @Test
    void acvpSignatureVerificationVectors() throws Exception {
        JsonNode root = readVectors("sig-ver.json");
        for (JsonNode group : root.withArray("testGroups")) {
            MLDSAParameterSet params = mapParameterSet(group.get("parameterSet").asText());
            int tgId = group.get("tgId").asInt();
            byte[] publicKey = hexBytes(group.get("pk"));
            for (JsonNode test : group.withArray("tests")) {
                int tcId = test.get("tcId").asInt();
                boolean expected = test.get("testPassed").asBoolean();
                String reason = test.has("reason") ? test.get("reason").asText() : "";
                byte[] message = hexBytes(test.get("message"));
                byte[] signature = hexBytes(test.get("signature"));

                boolean actual;
                try {
                    // Use verifyRaw for ACVP vectors (no domain separation)
                    actual = MLDSA.verifyRaw(params, publicKey, message, signature);
                } catch (IllegalArgumentException e) {
                    actual = false;
                }

                assertEquals(expected, actual,
                        "SigVer mismatch: tgId=" + tgId + " tcId=" + tcId +
                                " params=" + params + " reason=" + reason);
            }
        }
    }

    private static JsonNode readVectors(String name) throws IOException {
        String resource = "/mldsa/vectors/" + name;
        try (InputStream input = ACVPVectorTests.class.getResourceAsStream(resource)) {
            if (input == null) {
                throw new IllegalStateException("Missing test vector resource: " + resource);
            }
            return MAPPER.readTree(input);
        }
    }

    private static byte[] hexBytes(JsonNode node) {
        return HEX.parseHex(node.asText());
    }

    private static MLDSAParameterSet mapParameterSet(String name) {
        return switch (name) {
            case "ML-DSA-44" -> MLDSAParameterSet.ML_DSA_44;
            case "ML-DSA-65" -> MLDSAParameterSet.ML_DSA_65;
            case "ML-DSA-87" -> MLDSAParameterSet.ML_DSA_87;
            default -> throw new IllegalArgumentException("Unknown parameter set: " + name);
        };
    }
}
