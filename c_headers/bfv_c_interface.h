#ifndef BFV_C_INTERFACE_H
#define BFV_C_INTERFACE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque pointer types for BFV objects
typedef void* bfv_parameters_t;
typedef void* bfv_context_t;
typedef void* bfv_secret_key_t;
typedef void* bfv_evaluation_key_t;
typedef void* bfv_plaintext_t;
typedef void* bfv_ciphertext_t;

bfv_ciphertext_t bfv_sub_plaintext(bfv_ciphertext_t ciphertext, bfv_plaintext_t plaintext);

// Error handling
const char* bfv_get_last_error(void);
void bfv_free_string(char* str);

// Parameter creation
bfv_parameters_t bfv_create_parameters_from_preset(int32_t preset);
void bfv_free_parameters(bfv_parameters_t params);

// Context creation
bfv_context_t bfv_create_context(bfv_parameters_t params);
void bfv_free_context(bfv_context_t context);

// Key generation
bfv_secret_key_t bfv_generate_secret_key(bfv_context_t context);
void bfv_free_secret_key(bfv_secret_key_t key);

bfv_evaluation_key_t bfv_generate_evaluation_key(bfv_context_t context, bfv_secret_key_t secret_key);
void bfv_free_evaluation_key(bfv_evaluation_key_t key);

// Encoding/encryption
bfv_plaintext_t bfv_encode_int_array(bfv_context_t context, const int64_t* values, int32_t count);
void bfv_free_plaintext(bfv_plaintext_t plaintext);

bfv_ciphertext_t bfv_encrypt(bfv_plaintext_t plaintext, bfv_secret_key_t secret_key);
void bfv_free_ciphertext(bfv_ciphertext_t ciphertext);

// Decryption/decoding
bfv_plaintext_t bfv_decrypt(bfv_ciphertext_t ciphertext, bfv_secret_key_t secret_key);
bool bfv_decode_to_int_array(bfv_plaintext_t plaintext, int64_t* result_array, 
                             int32_t max_count, int32_t* actual_count);

// Homomorphic operations
bfv_ciphertext_t bfv_add(bfv_ciphertext_t lhs, bfv_ciphertext_t rhs);
bfv_ciphertext_t bfv_sub(bfv_ciphertext_t lhs, bfv_ciphertext_t rhs);
bfv_ciphertext_t bfv_multiply(bfv_ciphertext_t lhs, bfv_ciphertext_t rhs, 
                             bfv_evaluation_key_t eval_key);
bfv_ciphertext_t bfv_negate(bfv_ciphertext_t ciphertext);
bfv_ciphertext_t bfv_add_plaintext(bfv_ciphertext_t ciphertext, bfv_plaintext_t plaintext);

// Utility functions
double bfv_get_noise_budget(bfv_ciphertext_t ciphertext, bfv_secret_key_t secret_key);

#ifdef __cplusplus
}
#endif

#endif // BFV_C_INTERFACE_H