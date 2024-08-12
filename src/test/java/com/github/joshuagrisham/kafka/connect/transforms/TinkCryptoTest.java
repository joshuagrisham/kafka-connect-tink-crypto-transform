package com.github.joshuagrisham.kafka.connect.transforms;

import static org.apache.kafka.connect.transforms.util.Requirements.requireStruct;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Map;

import org.apache.kafka.connect.data.Schema;
import org.apache.kafka.connect.data.SchemaBuilder;
import org.apache.kafka.connect.data.Struct;
import org.apache.kafka.connect.source.SourceRecord;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import com.github.joshuagrisham.kafka.connect.transforms.TinkCrypto.ConfigName;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;

public class TinkCryptoTest {

    private final TinkCrypto<SourceRecord> xfKey1 = new TinkCrypto.Key<>();
    private final TinkCrypto<SourceRecord> xfKey2 = new TinkCrypto.Key<>();
    private final TinkCrypto<SourceRecord> xfValue1 = new TinkCrypto.Value<>();
    private final TinkCrypto<SourceRecord> xfValue2 = new TinkCrypto.Value<>();

    final String KEYSET = "{\"primaryKeyId\":2354067343,\"key\":[{\"keyData\":{\"typeUrl\":\"type.googleapis.com/google.crypto.tink.AesGcmKey\",\"value\":\"GiC67oOIK5gZHMWFEzjO5zuWBxlL3UONH5iM4ShKPalYlQ==\",\"keyMaterialType\":\"SYMMETRIC\"},\"status\":\"ENABLED\",\"keyId\":2354067343,\"outputPrefixType\":\"TINK\"}]}";

    private final Schema SCHEMA = SchemaBuilder.struct()
        .field("stringValue", SchemaBuilder.OPTIONAL_STRING_SCHEMA)
        .field("stringValue2", SchemaBuilder.OPTIONAL_STRING_SCHEMA)
        .field("stringValue3", SchemaBuilder.OPTIONAL_STRING_SCHEMA)
        .field("numberValue", SchemaBuilder.OPTIONAL_INT32_SCHEMA)
        .field("booleanValue", SchemaBuilder.OPTIONAL_BOOLEAN_SCHEMA)
        .optional()
        .build();
    private final Struct VALUE = new Struct(SCHEMA)
        .put("stringValue", "String value")
        .put("stringValue2", "String value #2")
        .put("stringValue3", "String value #3")
        .put("numberValue", 42)
        .put("booleanValue", true);
    private final Map<String, Object> VALUE_MAP = Map.of(
        "stringValue", "String value",
        "stringValue2", "String value #2",
        "stringValue3", "String value #3",
        "numberValue", 42,
        "booleanValue", true
    );

    @AfterEach
    public void teardown() {
        xfKey1.close();
        xfKey2.close();
        xfValue1.close();
        xfValue2.close();
    }

    @Test
    public void basicCryptoTest() throws GeneralSecurityException, IOException {
        // This test is basically a blueprint for the intended cryptographic actions which should be carried out by this SMT
        // (both encrypt and then decrypt)

        AeadConfig.register();
        KeysetHandle keysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withString(KEYSET));
        Aead aead = keysetHandle.getPrimitive(Aead.class);

        String plain = "tokenToBeEncrypted";

        // Encrypt:
        byte[] encrypted = aead.encrypt(plain.getBytes(), null);
        String encryptedB64 = Base64.getEncoder().encodeToString(encrypted);

        // Decrypt:
        byte[] encryptedFromB64 = Base64.getDecoder().decode(encryptedB64);
        byte[] decrypted = aead.decrypt(encryptedFromB64, null);
        String decryptedString = new String(decrypted);

        // Additional decrypt using pre-determined encrypted value:
        String predeterminedEncryptedB64 = "AYxQN49eXpPNOv+wPNRmX1/TsM29M37hHmRir8lgM9MP7g+dpAFc340omtRCxjcItd0U";
        byte[] predeterminedEncrypted = Base64.getDecoder().decode(predeterminedEncryptedB64);
        byte[] predeterminedDecrypted = aead.decrypt(predeterminedEncrypted, null);
        String predeterminedDecryptedString = new String(predeterminedDecrypted);

        assertEquals(plain, decryptedString);
        assertEquals(plain, predeterminedDecryptedString);
    }

    @Test
    public void basicCryptoTestWithAssociatedData() throws GeneralSecurityException, IOException {
        // Same as the above except this time we will also use associatedData

        AeadConfig.register();
        KeysetHandle keysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withString(KEYSET));
        Aead aead = keysetHandle.getPrimitive(Aead.class);

        String plain = "tokenToBeEncrypted";
        String associatedData = "for auth";

        // Encrypt:
        byte[] encrypted = aead.encrypt(plain.getBytes(), associatedData.getBytes());
        String encryptedB64 = Base64.getEncoder().encodeToString(encrypted);

        // Decrypt:
        byte[] encryptedFromB64 = Base64.getDecoder().decode(encryptedB64);
        byte[] decrypted = aead.decrypt(encryptedFromB64, associatedData.getBytes());
        String decryptedString = new String(decrypted);

        // Additional decrypt using pre-determined encrypted value:
        String predeterminedEncryptedB64 = "AYxQN49241lI8tdXvMROuqkKpHuCEXg2RexRhWny6CdkIE6HEpT0WzGrAERq/s2g0DfP";
        byte[] predeterminedEncrypted = Base64.getDecoder().decode(predeterminedEncryptedB64);
        byte[] predeterminedDecrypted = aead.decrypt(predeterminedEncrypted, associatedData.getBytes());
        String predeterminedDecryptedString = new String(predeterminedDecrypted);

        assertEquals(plain, decryptedString);
        assertEquals(plain, predeterminedDecryptedString);
    }

    @Test
    public void wholeRecordKeySchemaless() {
        xfKey1.configure(Map.of(
            ConfigName.MODE, TinkCrypto.MODE_ENCRYPT,
            ConfigName.KEYSET, KEYSET
            ,ConfigName.ASSOCIATED_DATA_VALUE, "test"
        ));
        xfKey2.configure(Map.of(
            ConfigName.MODE, TinkCrypto.MODE_DECRYPT,
            ConfigName.KEYSET, KEYSET
            ,ConfigName.ASSOCIATED_DATA_VALUE, "test"
        ));

        SourceRecord source = new SourceRecord(null, null, "topic", 0,
                null, "String value", null, null);
        SourceRecord encrypted = xfKey1.apply(source);
        SourceRecord decrypted = xfKey2.apply(encrypted);

        assertNull(encrypted.keySchema());
        assertNull(decrypted.keySchema());
        assertNotEquals(source.key(), encrypted.key());
        assertEquals(source.key(), decrypted.key());
    }

    @Test
    public void wholeRecordValueSchemaless() {
        xfValue1.configure(Map.of(
            ConfigName.MODE, TinkCrypto.MODE_ENCRYPT,
            ConfigName.KEYSET, KEYSET
        ));
        xfValue2.configure(Map.of(
            ConfigName.MODE, TinkCrypto.MODE_DECRYPT,
            ConfigName.KEYSET, KEYSET
        ));

        SourceRecord source = new SourceRecord(null, null, "topic", 0,
                null, null, null, "String value");
        SourceRecord encrypted = xfValue1.apply(source);
        SourceRecord decrypted = xfValue2.apply(encrypted);

        assertNull(encrypted.valueSchema());
        assertNull(decrypted.valueSchema());
        assertNotEquals(source.value(), encrypted.value());
        assertEquals(source.value(), decrypted.value());
    }

    @Test
    public void schemalessMap() {
        xfValue1.configure(Map.of(
            ConfigName.MODE, TinkCrypto.MODE_ENCRYPT,
            ConfigName.KEYSET, KEYSET,
            ConfigName.FIELDS, "stringValue,stringValue2",
            ConfigName.ASSOCIATED_DATA_FIELDS, "stringValue3,numberValue"
        ));
        xfValue2.configure(Map.of(
            ConfigName.MODE, TinkCrypto.MODE_DECRYPT,
            ConfigName.KEYSET, KEYSET,
            ConfigName.FIELDS, "stringValue,stringValue2",
            ConfigName.ASSOCIATED_DATA_FIELDS, "stringValue3,numberValue"
        ));

        SourceRecord source = new SourceRecord(null, null, "topic", 0,
                null, null, null, VALUE_MAP);
        SourceRecord encrypted = xfValue1.apply(source);
        SourceRecord decrypted = xfValue2.apply(encrypted);

        assertNull(encrypted.valueSchema());
        assertNull(decrypted.valueSchema());
        assertNotEquals(source.value(), encrypted.value());
        assertEquals(source.value(), decrypted.value());
    }

    @Test
    public void keyWithSchema() {
        xfKey1.configure(Map.of(
            ConfigName.MODE, TinkCrypto.MODE_ENCRYPT,
            ConfigName.KEYSET, KEYSET,
            ConfigName.FIELDS, "stringValue"
        ));
        xfKey2.configure(Map.of(
            ConfigName.MODE, TinkCrypto.MODE_DECRYPT,
            ConfigName.KEYSET, KEYSET,
            ConfigName.FIELDS, "stringValue"
        ));

        SourceRecord source = new SourceRecord(null, null, "topic", 0,
                SCHEMA, VALUE, null, null);
        SourceRecord encrypted = xfKey1.apply(source);
        SourceRecord decrypted = xfKey2.apply(encrypted);

        assertNotNull(encrypted.keySchema());
        assertNotNull(decrypted.keySchema());
        assertNotEquals(source.key(), encrypted.key());
        assertEquals(source.key(), decrypted.key());
    }

    @Test
    public void valueWithSchema() {
        xfValue1.configure(Map.of(
            ConfigName.MODE, TinkCrypto.MODE_ENCRYPT,
            ConfigName.KEYSET, KEYSET,
            ConfigName.FIELDS, "stringValue"
        ));
        xfValue2.configure(Map.of(
            ConfigName.MODE, TinkCrypto.MODE_DECRYPT,
            ConfigName.KEYSET, KEYSET,
            ConfigName.FIELDS, "stringValue"
        ));

        SourceRecord source = new SourceRecord(null, null, "topic", 0,
                null, null, SCHEMA, VALUE);
        SourceRecord encrypted = xfValue1.apply(source);
        SourceRecord decrypted = xfValue2.apply(encrypted);

        assertNotNull(encrypted.valueSchema());
        assertNotNull(decrypted.valueSchema());
        assertNotEquals(source.value(), encrypted.value());
        assertEquals(source.value(), decrypted.value());
    }

    @Test
    public void schemaFixedAssociatedData() {
        xfValue1.configure(Map.of(
            ConfigName.MODE, TinkCrypto.MODE_ENCRYPT,
            ConfigName.KEYSET, KEYSET,
            ConfigName.FIELDS, "stringValue",
            ConfigName.ASSOCIATED_DATA_VALUE, "A value for authorization"
        ));
        xfValue2.configure(Map.of(
            ConfigName.MODE, TinkCrypto.MODE_DECRYPT,
            ConfigName.KEYSET, KEYSET,
            ConfigName.FIELDS, "stringValue",
            ConfigName.ASSOCIATED_DATA_VALUE, "A value for authorization"
        ));

        SourceRecord source = new SourceRecord(null, null, "topic", 0,
                null, null, SCHEMA, VALUE);
        SourceRecord encrypted = xfValue1.apply(source);
        SourceRecord decrypted = xfValue2.apply(encrypted);

        assertNotNull(encrypted.valueSchema());
        assertNotNull(decrypted.valueSchema());
        assertNotEquals(source.value(), encrypted.value());
        assertEquals(source.value(), decrypted.value());
    }

    @Test
    public void schemaFieldAssociatedData() {
        xfValue1.configure(Map.of(
            ConfigName.MODE, TinkCrypto.MODE_ENCRYPT,
            ConfigName.KEYSET, KEYSET,
            ConfigName.FIELDS, "stringValue,numberValue,booleanValue",
            ConfigName.ASSOCIATED_DATA_FIELDS, "stringValue2,stringValue3,stringValue2"
        ));
        xfValue2.configure(Map.of(
            ConfigName.MODE, TinkCrypto.MODE_DECRYPT,
            ConfigName.KEYSET, KEYSET,
            ConfigName.FIELDS, "stringValue,numberValue,booleanValue",
            ConfigName.ASSOCIATED_DATA_FIELDS, "stringValue2,stringValue3,stringValue2"
        ));

        SourceRecord source = new SourceRecord(null, null, "topic", 0,
                null, null, SCHEMA, VALUE);
        SourceRecord encrypted = xfValue1.apply(source);
        SourceRecord decrypted = xfValue2.apply(encrypted);
        Struct decryptedStruct = requireStruct(decrypted.value(), TinkCryptoTest.class.getName());

        assertNotNull(encrypted.valueSchema());
        assertNotNull(decrypted.valueSchema());
        assertNotEquals(source.value(), encrypted.value());

        // here we know that numberValue and booleanValue would have been converted to strings, so check that toString() of the orignal value matches
        assertEquals(VALUE.get("stringValue"), decryptedStruct.get("stringValue"));
        assertEquals(VALUE.get("numberValue").toString(), decryptedStruct.get("numberValue"));
        assertEquals(VALUE.get("booleanValue").toString(), decryptedStruct.get("booleanValue"));
    }

}
