#ifndef PROTOBUF_C_INTERFACE_H
#define PROTOBUF_C_INTERFACE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* bfv_context_t;
typedef void* bfv_plaintext_t;
typedef void* bfv_ciphertext_t;

// Serialize a ciphertext to Protobuf bytes
// Returns number of bytes, or 0 on error. out_bytes must be freed by bfv_free_bytes.
size_t bfv_serialize_ciphertext_to_protobuf(bfv_ciphertext_t ct, uint8_t** out_bytes);

// Deserialize Protobuf bytes to ciphertext
bfv_ciphertext_t bfv_deserialize_ciphertext_from_protobuf(const uint8_t* bytes, size_t len, bfv_context_t ctx);

// Serialize a plaintext to Protobuf bytes
size_t bfv_serialize_plaintext_to_protobuf(bfv_plaintext_t pt, uint8_t** out_bytes);

// Deserialize Protobuf bytes to plaintext
bfv_plaintext_t bfv_deserialize_plaintext_from_protobuf(const uint8_t* bytes, size_t len, bfv_context_t ctx);

// Free a byte buffer allocated by Swift
void bfv_free_bytes(uint8_t* bytes);

#ifdef __cplusplus
}
#endif

#endif // PROTOBUF_C_INTERFACE_H