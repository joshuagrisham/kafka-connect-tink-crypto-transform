# Kafka Connect Google Tink Crypto Transform (SMT)

Kafka Connect Single Message Transform (SMT) to encrypt or decrypt an entire value string or selected fields using the [Google Tink cryptography library](https://developers.google.com/tink).

Currently, only the [Authenticated Encryption with Associated Data (AEAD)](https://developers.google.com/tink/aead) primitive is implemented. Any key type supported by Tink's AEAD implementation should also be supported with this SMT.

Keysets can be generated and managed using the [Tinkey](https://developers.google.com/tink/tinkey-overview) utility and recommended to be passed into your connector using the [ConfigProvider](https://kafka.apache.org/38/javadoc/org/apache/kafka/common/config/provider/ConfigProvider.html) of your choice (e.g. through some kind of external secrets provider).

It should be possible to use any of the available Google Tink clients to decrypt and encrypt values which are used together with this SMT, provided that you are using the same Tink keyset. As of this writing there are clients available in C++, Go, Java, ObjC, and Python (see [Tink setup](https://developers.google.com/tink/tink-setup) for more information). I have personally tested successfully with Java, Python, and Go.

The basic intended blueprint for encrypting and decrypting with this SMT can be seen in one of the unit test examples, but in essence it is as follows:

```java
AeadConfig.register();
KeysetHandle keysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withString(KEYSET_JSON_STRING));
Aead aead = keysetHandle.getPrimitive(Aead.class);

String plain = "tokenToBeEncrypted";

// Encrypt:
byte[] encrypted = aead.encrypt(plain.getBytes(), null); // encrypt without setting optional associatedData
String encryptedB64 = Base64.getEncoder().encodeToString(encrypted);

// Decrypt:
byte[] encryptedFromB64 = Base64.getDecoder().decode(encryptedB64);
byte[] decrypted = aead.decrypt(encryptedFromB64, null); // decrypt without setting optional associatedData
String decryptedString = new String(decrypted);
```

And if you **_really_** want to streamline, then it should also be entirely possible to decrypt and encrypt the payloads using completely standard libraries (e.g. Java's `javax.crypto.Cipher`, Go's `crypto/cipher`, etc), provided that the payload and all of the initialization values are set in a way that match Tink's various implementations (e.g. concatenate the `primaryKeyId` from the keyset with the payload and set the correct nonce and authentication tag, etc; see <https://github.com/tink-crypto/tink/blob/master/go/aead/aead_factory.go> and <https://github.com/tink-crypto/tink/blob/master/go/aead/subtle/aes_gcm_siv.go> for some inspiration).

## Data types

All values encrypted by this SMT will be handled as a string data type. If a value is given with any other data type, it will first be converted to a plaintext string before then being encrypted. Once encrypted, the encrypted byte array will then be encoded into a Base64-encoded string. This is done primarily to allow portability of the payloads used by this SMT so that they may work well with other languages and platforms. Note that usage of any data types which are not supported (i.e. not a primitive or a primitive wrapper that can natively be converted to a string) will result in an error during execution of the transformation.

The core issue is with differences in endian-ness of various data formats in various languages and libraries. For example, Java uses Big Endian for numeric types by default while Go uses Little Endian. Since data encryption happens on the byte level (e.g. byte arrays), this can cause problems in a mixed-usage landscape (e.g. encrypting a an int32 of `42` using Go would result in the array `[42,0,0,0]`, but a similar int in Java would by default expected to be represented by the byte array `[0,0,0,42]`; this is a much different value if it is interpreted in the wrong way!).

Since strings (i.e. arrays of characters) always follow a WYSIWYG sequence, they do not suffer from this problem.

And, in line with the above, the decryption operation will always expect the encrypted value to be a Base64-encoded string, and will subsequently store the resulted decrypted text as a string data type.

## Background

Inspired by [Kryptonite for Kafka](https://github.com/hpgrahsl/kryptonite-for-kafka) but tries to overcome the following issues:

- Reliance on many additional dependencies including multiple external cryptography and data format libraries, which cause a fair amount of headaches when trying to use and deploy it in various settings (it cannot be built by JitPack, for example)
- Proprietary payload format which makes it largely impossible to encrypt or decrypt values outside of using Kryptonite in Java (see above regarding dependency issues which can make this more difficult), or using the provided Funqy-based HTTP service runtime (which, by the way, always expects and wraps even single-element data as valid JSON, which means you might always need to do some pre- and post-processing of the payloads if you want to use this service)
- Semi-proprietary Tink keyset configuration format (more specifically, an wrapper around Tink keysets) which can lead to the need for additional pre-processing or transformation of configuration data in your implementation

This `TinkCrypto` SMT tries address the above as follows:

- Use of no additional dependencies outside of `com.google.crypto.tink:tink` and what will already be present in the Connect runtime (namely, using only what comes under `org.apache.kafka:connect-transforms`)
- Tries to stick to a [KISS design principle](https://en.wikipedia.org/wiki/KISS_principle) as much as possible; uses Tink's AEAD primitive largely "as-is" with not much logic in-between, which allows for portability of using the payloads with other Tink clients (Go, Java, Python, etc)
- Produces a shaded JAR by default which includes the as-configured version of Google Tink and its dependencies and is supported by various dynamic build systems such as JitPack
- Tink Keysets are used in their original data format and as such will not require any special handling (outside of somehow making them available e.g. with a `ConfigProvider`) before using them directly with your connector's configuration

## Potential improvements

- Support to address nested fields, potentially using a dot-based notation (currently only root-level fields are supported).
- Possible ability to support data types other than only string

## Installation

I have not yet really deployed this anywhere, but it should be quite easy to fetch the the shaded JAR (around 4.5MB) from the latest release here and put it into your Kafka Connect plugins folder.

You can also fetch it via <https://jitpack.io> using Maven, Gradle, etc if desired.

## Examples

Encrypt two Value fields without using `associatedData`:

```sh
"transforms": "encrypt",
"transforms.encrypt.type": "com.github.joshuagrisham.kafka.connect.transforms.TinkCrypto$Value",
"transforms.encrypt.mode": "encrypt",
"transforms.encrypt.keyset": "{\"primaryKeyId\":2354067343,\"key\":[{\"keyData\":{\"typeUrl\":\"type.googleapis.com/google.crypto.tink.AesGcmKey\",\"value\":\"GiC67oOIK5gZHMWFEzjO5zuWBxlL3UONH5iM4ShKPalYlQ==\",\"keyMaterialType\":\"SYMMETRIC\"},\"status\":\"ENABLED\",\"keyId\":2354067343,\"outputPrefixType\":\"TINK\"}]}",
"transforms.encrypt.fields": "someTextField,anotherTextField",
```

Decrypt two Value fields using a hard-coded `associatedData` value (and this time setting the keyset value with a configured `ConfigProvider` called `secrets`):

```sh
"transforms": "decrypt",
"transforms.decrypt.type": "com.github.joshuagrisham.kafka.connect.transforms.TinkCrypto$Value",
"transforms.decrypt.mode": "decrypt",
"transforms.decrypt.keyset": "${secrets:my-namespace/some-keyset-secret:keyset.json}",
"transforms.decrypt.fields": "someTextField,anotherTextField",
"transforms.decrypt.associateddata.value": "a pre-determined hard-coded auth value used during encryption",
```

Encrypt four Key fields using another field in the payload as their `associatedData` (in this case, I wanted to use the value of the field `transactionId` as the `associatedData` for all four fields):

```sh
"transforms": "encrypt",
"transforms.encrypt.type": "com.github.joshuagrisham.kafka.connect.transforms.TinkCrypto$Key",
"transforms.encrypt.mode": "encrypt",
"transforms.encrypt.keyset": "${secrets:my-namespace/some-keyset-secret:keyset.json}",
"transforms.encrypt.fields": "oneField,twoField,redField,blueField",
"transforms.encrypt.associateddata.fields": "transactionId,transactionId,transactionId,transactionId",
```
