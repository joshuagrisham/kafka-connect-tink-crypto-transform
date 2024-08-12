package com.github.joshuagrisham.kafka.connect.transforms;

import static org.apache.kafka.connect.transforms.util.Requirements.requireMap;
import static org.apache.kafka.connect.transforms.util.Requirements.requireStruct;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.kafka.common.cache.Cache;
import org.apache.kafka.common.cache.LRUCache;
import org.apache.kafka.common.cache.SynchronizedCache;
import org.apache.kafka.common.config.ConfigDef;
import org.apache.kafka.common.config.ConfigException;
import org.apache.kafka.connect.connector.ConnectRecord;
import org.apache.kafka.connect.data.Field;
import org.apache.kafka.connect.data.Schema;
import org.apache.kafka.connect.data.SchemaBuilder;
import org.apache.kafka.connect.data.Struct;
import org.apache.kafka.connect.errors.DataException;
import org.apache.kafka.connect.transforms.Transformation;
import org.apache.kafka.connect.transforms.util.SchemaUtil;
import org.apache.kafka.connect.transforms.util.SimpleConfig;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;

public abstract class TinkCrypto<R extends ConnectRecord<R>> implements Transformation<R> {

    public static final String OVERVIEW_DOC =
            "Encrypts or decrypts an entire value string or specified fields using the Google Tink cryptography "
                    + "library. To avoid cross-platform problems due to variations in endian-ness, all selected values "
                    + "will be converted to string before encrypting, and be assumed to be strings when decrypting. Values "
                    + "themselves will be saved as Base64-encoded strings for portability and the decrypt mode operation "
                    + "will also expect the payload to be stored as a Base64-encoded string."
                    + "<p/>When not using a schema, only maps and entire values are supported at this time."
                    + "<p/>When using a schema, only root-level fields are supported at this time."
                    + "<p/>Use the concrete transformation type designed for the record key (<code>" + Key.class.getName()
                    + "</code>) or value (<code>" + Value.class.getName() + "</code>).";

    public interface ConfigName {
        String MODE = "mode";
        String KEYSET = "keyset";
        String FIELDS = "fields";
        String ASSOCIATED_DATA_VALUE = "associateddata.value";
        String ASSOCIATED_DATA_FIELDS = "associateddata.fields";
    }

    public static final String MODE_ENCRYPT = "encrypt";
    public static final String MODE_DECRYPT = "decrypt";

    public static final ConfigDef CONFIG_DEF = new ConfigDef()
            .define(ConfigName.MODE, ConfigDef.Type.STRING, ConfigDef.NO_DEFAULT_VALUE,
                    ConfigDef.ValidString.in(MODE_ENCRYPT, MODE_DECRYPT), ConfigDef.Importance.HIGH,
                    "Which operation ('" + MODE_ENCRYPT + "' or '" + MODE_DECRYPT + "') to perform on the given '"
                            + ConfigName.FIELDS + "' using the given '" + ConfigName.KEYSET + "' specification.")
            .define(ConfigName.KEYSET, ConfigDef.Type.STRING, ConfigDef.NO_DEFAULT_VALUE, ConfigDef.Importance.HIGH,
                    "Google Tink Keyset specification in JSON format. Can be created with the tinkey utility "
                            + "(example: <code>tinkey create-keyset --key-template=AES256_GCM</code>). See "
                            + "https://developers.google.com/tink/key-management-overview for more information.")
            .define(ConfigName.FIELDS, ConfigDef.Type.LIST, null, ConfigDef.Importance.MEDIUM,
                    "List of field names on which to perform the given cipher mode operation, or empty to process the "
                            + "entire value.")
            .define(ConfigName.ASSOCIATED_DATA_VALUE, ConfigDef.Type.STRING, null, ConfigDef.Importance.LOW,
                    "Hard-coded value which should be used to provide additional data for encryption authentication. "
                            + "Can be omitted if you do not wish to use associated data authentication. Should not be "
                            + "used together with " + ConfigName.ASSOCIATED_DATA_FIELDS + ".")
            .define(ConfigName.ASSOCIATED_DATA_FIELDS, ConfigDef.Type.LIST, null, ConfigDef.Importance.LOW,
                    "Names of fields which should be used to provide additional data for encryption authentication. "
                            + "The position of the field name in this list will be matched to the position in the "
                            + ConfigName.ASSOCIATED_DATA_FIELDS + " property so that each field's additional data can "
                            + "each have different values. Can be omitted if you do not wish to use associated data "
                            + "authentication. Should not be used together with " + ConfigName.ASSOCIATED_DATA_VALUE + ".");

    private static final String PURPOSE = "encrypt or decrypt fields";

    private String mode;
    private String keyset;
    private List<String> fields;
    private String associatedDataValue;
    private List<String> associatedDataFields;
    private Aead TINK;

    private Cache<Schema, Schema> schemaUpdateCache;

    @Override
    public void configure(Map<String, ?> props) {

        final SimpleConfig config = new SimpleConfig(CONFIG_DEF, props);

        mode = config.getString(ConfigName.MODE);
        keyset = config.getString(ConfigName.KEYSET);
        fields = config.getList(ConfigName.FIELDS);
        associatedDataValue = config.getString(ConfigName.ASSOCIATED_DATA_VALUE);
        associatedDataFields = config.getList(ConfigName.ASSOCIATED_DATA_FIELDS);

        // if ASSOCIATED_DATA_FIELDS have been configured, control that the other config values are correct before allowing to continue
        if (hasAssociatedDataFields()) {
            if (associatedDataValue != null && !associatedDataValue.isEmpty()) {
                throw new ConfigException(String.format("'%s' and '%s' are mutually exclusive and must not be used together",
                    ConfigName.ASSOCIATED_DATA_FIELDS, ConfigName.ASSOCIATED_DATA_VALUE));
            } else {
                if (associatedDataFields.size() != fields.size()) {
                    throw new ConfigException(String.format("number of fields specified in '%s' and '%s' must match; "
                            + "otherwise, a fixed value can be provided for use in all fields with '%s'",
                        ConfigName.FIELDS, ConfigName.ASSOCIATED_DATA_FIELDS, ConfigName.ASSOCIATED_DATA_VALUE));
                }
            }
        }

        schemaUpdateCache = new SynchronizedCache<>(new LRUCache<>(16));

        try {
            // Register all AEAD key types with the Tink runtime.
            AeadConfig.register();
            // Read the keyset into a KeysetHandle.
            KeysetHandle handle = CleartextKeysetHandle.read(JsonKeysetReader.withString(keyset));
            // Get the primitive.
            TINK = handle.getPrimitive(Aead.class);
        } catch (GeneralSecurityException | IOException e) {
            throw new ConfigException("exception when attempting to set up the Tink cryptography runtime: " + e.getMessage());
        }

    }

    @Override
    public R apply(R record) {
        if (operatingValue(record) == null) {
            return record;
        }

        if (operatingSchema(record) == null) {
            return applySchemaless(record);
        } else {
            return applyWithSchema(record);
        }
    }

    private R applySchemaless(R record) {
        if (fields != null && !fields.isEmpty()) {
            // assume that schemaless value with fields specified is a map; apply cipher operation to map entries
            final Map<String, Object> value = requireMap(operatingValue(record), PURPOSE);
            final HashMap<String, Object> updatedValue = new HashMap<>(value);
            for (String field : fields) {
                String associatedData;
                if (hasAssociatedDataFields()) {
                    // if associatedData is configured per field, use the associatedData field's value in the cipher
                    associatedData = valueAsString(value.get(associatedDataFields.get(fields.indexOf(field))));
                } else {
                    // otherwise, use the fixed value associatedDataValue (or empty byte array)
                    associatedData = associatedDataValue;
                }
                updatedValue.put(field, cipher(valueAsString(value.get(field)), associatedData));
            }
            return newRecord(record, null, updatedValue);
        } else {
            // convert the entire value
            return newRecord(record, null, cipher(valueAsString(operatingValue(record)), associatedDataValue));
        }
    }

    private R applyWithSchema(R record) {
        if (fields == null || fields.isEmpty()) {
            throw new DataException("Encrypting or decrypting the entire value is not supported for records with a schema. "
                    + "Try transforming one or more specific fields or make the necessary adjustments so that your records will "
                    + "not have a schema.");
        }

        Schema valueSchema = operatingSchema(record);
        Schema updatedSchema = getOrBuildSchema(valueSchema);

        final Struct value = requireStruct(operatingValue(record), PURPOSE);

        final Struct updatedValue = new Struct(updatedSchema);
        for (Field field : value.schema().fields()) {
            if (fields.contains(field.name())) {
                String associatedData;
                if (hasAssociatedDataFields()) {
                    // if associatedData is configured per field, use the associatedData field's value in the cipher
                    associatedData = valueAsString(value.get(associatedDataFields.get(fields.indexOf(field.name()))));
                } else {
                    // otherwise, use the fixed value associatedDataValue (or empty byte array)
                    associatedData = associatedDataValue;
                }
                updatedValue.put(updatedSchema.field(field.name()),
                    cipher(valueAsString(value.get(field.name())), associatedData));
            } else {
                updatedValue.put(field, value.get(field));
            }
        }
        return newRecord(record, updatedSchema, updatedValue);
    }

    private Schema getOrBuildSchema(Schema valueSchema) {
        Schema updatedSchema = schemaUpdateCache.get(valueSchema);
        if (updatedSchema != null)
            return updatedSchema;

        final SchemaBuilder builder = SchemaUtil.copySchemaBasics(valueSchema, SchemaBuilder.struct());
        for (Field field : valueSchema.fields()) {
            if (fields.contains(field.name())) {
                // we will always use string to avoid differences in endian-ness in different platforms and languages (e.g. Go vs Java)
                SchemaBuilder fieldBuilder = SchemaBuilder.string();
                if (field.schema().isOptional())
                    fieldBuilder.optional();
                builder.field(field.name(), fieldBuilder.build());
            } else {
                builder.field(field.name(), field.schema());
            }
        }

        if (valueSchema.isOptional())
            builder.optional();

        updatedSchema = builder.build();
        schemaUpdateCache.put(valueSchema, updatedSchema);
        return updatedSchema;
    }

    private boolean hasAssociatedDataFields() {
        return (associatedDataFields != null && associatedDataFields.size() > 0);
    }

    private List<Class<?>> supportedWrapperClasses = List.of(
        Boolean.class,
        Character.class,
        Short.class,
        Integer.class,
        Long.class,
        Float.class,
        Double.class
    );

    private String valueAsString(Object value) {
        if (value == null)
            return null;
        if (value instanceof String)
            return value.toString();
        Class<?> clazz = value.getClass();
        if (clazz.isPrimitive() || supportedWrapperClasses.contains(clazz))
            return value.toString();
        throw new DataException(String.format("unsupported data type class '%s' when attempting to convert value '%s' to string",
            clazz.getName(), value));
    }

    private Object cipher(String value, String associatedData) {
        if (value == null)
            return null;
        byte[] associatedDataBytes;
        if (associatedData != null && !associatedData.isEmpty())
            associatedDataBytes = associatedData.getBytes();
        else
            associatedDataBytes = null;

        if (mode.equals(MODE_ENCRYPT)) {
            try {
                byte[] encrypted = TINK.encrypt(value.getBytes(), associatedDataBytes);
                return Base64.getEncoder().encodeToString(encrypted);
            } catch (GeneralSecurityException e) {
                throw new DataException(e);
            }
        } else if (mode.equals(MODE_DECRYPT)) {
            byte[] encrypted = Base64.getDecoder().decode(value.toString());
            try {
                byte[] decrypted = TINK.decrypt(encrypted, associatedDataBytes);
                return new String(decrypted);
            } catch (GeneralSecurityException e) {
                throw new DataException(e);
            }
        }

        return null;
    }

    @Override
    public ConfigDef config() {
        return CONFIG_DEF;
    }

    @Override
    public void close() {
    }

    protected abstract Schema operatingSchema(R record);

    protected abstract Object operatingValue(R record);

    protected abstract R newRecord(R record, Schema updatedSchema, Object updatedValue);

    protected abstract String recordType();

    public static final class Key<R extends ConnectRecord<R>> extends TinkCrypto<R> {
        @Override
        protected Schema operatingSchema(R record) {
            return record.keySchema();
        }

        @Override
        protected Object operatingValue(R record) {
            return record.key();
        }

        @Override
        protected R newRecord(R record, Schema updatedSchema, Object updatedValue) {
            return record.newRecord(record.topic(), record.kafkaPartition(), updatedSchema, updatedValue, record.valueSchema(), record.value(), record.timestamp());
        }

        @Override
        protected String recordType() {
            return "key";
        }
    }

    public static final class Value<R extends ConnectRecord<R>> extends TinkCrypto<R> {
        @Override
        protected Schema operatingSchema(R record) {
            return record.valueSchema();
        }

        @Override
        protected Object operatingValue(R record) {
            return record.value();
        }

        @Override
        protected R newRecord(R record, Schema updatedSchema, Object updatedValue) {
            return record.newRecord(record.topic(), record.kafkaPartition(), record.keySchema(), record.key(), updatedSchema, updatedValue, record.timestamp());
        }

        @Override
        protected String recordType() {
            return "value";
        }
    }

}
