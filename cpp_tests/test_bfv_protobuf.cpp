#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "bfv_c_interface.h"         // Your core C interface
#include "protobuf_c_interface.h"    // Your Protobuf C interface

//int main() {
//    printf("=== BFV Protobuf Serialization Test ===\n");
//
//    // 1. Create parameters and context
//    bfv_parameters_t params = bfv_create_parameters_from_preset(2);
//    assert(params && "Failed to create parameters");
//    bfv_context_t ctx = bfv_create_context(params);
//    assert(ctx && "Failed to create context");
//
//    // 2. Generate secret key
//    bfv_secret_key_t sk = bfv_generate_secret_key(ctx);
//    assert(sk && "Failed to generate secret key");
//
//    // 3. Encode and encrypt a plaintext
//    int64_t values[1] = {42};
//    bfv_plaintext_t pt = bfv_encode_int_array(ctx, values, 1);
//    assert(pt && "Failed to encode plaintext");
//    bfv_ciphertext_t ct = bfv_encrypt(pt, sk);
//    assert(ct && "Failed to encrypt");
//
//    // 4. Serialize ciphertext to Protobuf bytes
//    uint8_t* ct_bytes = nullptr;
//    size_t ct_len = bfv_serialize_ciphertext_to_protobuf(ct, &ct_bytes);
//    assert(ct_len > 0 && ct_bytes && "Failed to serialize ciphertext");
//
//    // 5. Deserialize bytes back to ciphertext
//    bfv_ciphertext_t ct2 = bfv_deserialize_ciphertext_from_protobuf(ct_bytes, ct_len, ctx);
//    if (!ct2) {
//    const char* err = bfv_get_last_error();
//    if (err) {
//        printf("Swift error: %s\n", err);
//        bfv_free_string(err);
//    }
//}
//    assert(ct2 && "Failed to deserialize ciphertext");
//
//    // 6. Decrypt and decode
//    bfv_plaintext_t pt2 = bfv_decrypt(ct2, sk);
//    assert(pt2 && "Failed to decrypt deserialized ciphertext");
//    int64_t result[1] = {0};
//    int32_t actualCount = 0;
//    int ok = bfv_decode_to_int_array(pt2, result, 1, &actualCount);
//    assert(ok && actualCount == 1);
//    printf("Decrypted value after round-trip: %ld\n", result[0]);
//    assert(result[0] == 42);
//
//    // 7. Clean up
//    bfv_free_bytes(ct_bytes);
//    bfv_free_parameters(params);
//    bfv_free_context(ctx);
//    bfv_free_secret_key(sk);
//    bfv_free_plaintext(pt);
//    bfv_free_ciphertext(ct);
//    bfv_free_ciphertext(ct2);
//    bfv_free_plaintext(pt2);
//
//    printf("All Protobuf serialization tests passed!\n");
//    return 0;
//}

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "bfv_c_interface.h"
#include "protobuf_c_interface.h"

int main() {
    printf("Step 1: Creating parameters and context\n");
    bfv_parameters_t params = bfv_create_parameters_from_preset(2);
    assert(params && "Failed to create parameters");
    bfv_context_t ctx = bfv_create_context(params);
    assert(ctx && "Failed to create context");

    printf("Step 2: Generating secret key\n");
    bfv_secret_key_t sk = bfv_generate_secret_key(ctx);
    assert(sk && "Failed to generate secret key");

    printf("Step 3: Encoding and encrypting plaintext\n");
    int64_t values[1] = {42};
    bfv_plaintext_t pt = bfv_encode_int_array(ctx, values, 1);
    assert(pt && "Failed to encode plaintext");
    bfv_ciphertext_t ct = bfv_encrypt(pt, sk);
    assert(ct && "Failed to encrypt");

    printf("Step 4: Serializing ciphertext to Protobuf bytes\n");
    uint8_t* ct_bytes = nullptr;
    size_t ct_len = bfv_serialize_ciphertext_to_protobuf(ct, &ct_bytes);
    assert(ct_len > 0 && ct_bytes && "Failed to serialize ciphertext");

    printf("Step 5: Deserializing bytes back to ciphertext\n");
    bfv_ciphertext_t ct2 = bfv_deserialize_ciphertext_from_protobuf(ct_bytes, ct_len, ctx);
    if (!ct2) {
        const char* err = bfv_get_last_error();
        if (err) {
            printf("Swift error: %s\n", err);
            bfv_free_string(err);
        }
    }
    assert(ct2 && "Failed to deserialize ciphertext");

    printf("Step 6: Decrypting and decoding\n");
    bfv_plaintext_t pt2 = bfv_decrypt(ct2, sk);
    assert(pt2 && "Failed to decrypt deserialized ciphertext");
    int64_t result[1] = {0};
    int32_t actualCount = 0;
    int ok = bfv_decode_to_int_array(pt2, result, 1, &actualCount);
    assert(ok && actualCount == 1);
    printf("Decrypted value after round-trip: %ld\n", result[0]);
    assert(result[0] == 42);

    printf("Step 7: Cleaning up\n");
    bfv_free_bytes(ct_bytes);
    bfv_free_parameters(params);
    bfv_free_context(ctx);
    bfv_free_secret_key(sk);
    bfv_free_plaintext(pt);
    bfv_free_ciphertext(ct);
    bfv_free_ciphertext(ct2);
    bfv_free_plaintext(pt2);

    printf("All Protobuf serialization tests passed!\n");
    return 0;
}