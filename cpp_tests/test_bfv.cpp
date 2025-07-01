#include <stdio.h>
#include "bfv_c_interface.h"

int main() {
    // Create parameters using a predefined set
    void* params = bfv_create_parameters_from_preset(1);  // n_4096_logq_27_28_28_logt_5
    if (!params) {
        printf("Error creating parameters: %s\n", bfv_get_last_error());
        return 1;
    }
    
    // Create context
    void* context = bfv_create_context(params);
    if (!context) {
        printf("Error creating context: %s\n", bfv_get_last_error());
        bfv_free_parameters(params);
        return 1;
    }
    
    // Generate keys
    void* secret_key = bfv_generate_secret_key(context);
    void* eval_key = bfv_generate_evaluation_key(context, secret_key);
    
    // Encode and encrypt some data
    int64_t values[] = {1, 2, 3, 4, 5, 6, 7, 8};
    void* plaintext = bfv_encode_int_array(context, values, 8);
    void* ciphertext = bfv_encrypt(plaintext, secret_key);
    
    // Perform homomorphic operations
    void* ciphertext2 = bfv_encrypt(plaintext, secret_key);
    void* sum = bfv_add(ciphertext, ciphertext2);
    void* product = bfv_multiply(ciphertext, ciphertext2, eval_key);
    
    // Decrypt and decode results
    void* decrypted_sum = bfv_decrypt(sum, secret_key);
    void* decrypted_product = bfv_decrypt(product, secret_key);
    
    // Get the results
    int64_t result_sum[8];
    int64_t result_product[8];
    int32_t actual_count_sum, actual_count_product;
    
    bfv_decode_to_int_array(decrypted_sum, result_sum, 8, &actual_count_sum);
    bfv_decode_to_int_array(decrypted_product, result_product, 8, &actual_count_product);
    
    // Print results
    printf("Sum result: ");
    for (int i = 0; i < actual_count_sum; i++) {
        printf("%lld ", result_sum[i]);
    }
    printf("\n");
    
    printf("Product result: ");
    for (int i = 0; i < actual_count_product; i++) {
        printf("%lld ", result_product[i]);
    }
    printf("\n");
    
    // Clean up
    bfv_free_ciphertext(product);
    bfv_free_ciphertext(sum);
    bfv_free_ciphertext(ciphertext2);
    bfv_free_ciphertext(ciphertext);
    bfv_free_plaintext(decrypted_product);
    bfv_free_plaintext(decrypted_sum);
    bfv_free_plaintext(plaintext);
    bfv_free_evaluation_key(eval_key);
    bfv_free_secret_key(secret_key);
    bfv_free_context(context);
    bfv_free_parameters(params);
    
    return 0;
}