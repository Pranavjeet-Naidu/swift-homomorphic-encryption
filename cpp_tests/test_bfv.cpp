// File: test_bfv_c_interface.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "bfv_c_interface.h" // Adjust path if needed

int main() {
    printf("=== BFV Homomorphic Encryption Test ===\n\n");
    
    // 1. Create parameters
    void* params = bfv_create_parameters_from_preset(2);
    assert(params && "Failed to create parameters");
    printf("1. Parameters created successfully\n");

    // 2. Create context
    void* ctx = bfv_create_context(params);
    assert(ctx && "Failed to create context");
    printf("2. Context created successfully\n");

    // 3. Generate secret key
    void* sk = bfv_generate_secret_key(ctx);
    assert(sk && "Failed to generate secret key");
    printf("3. Secret key generated successfully\n");

    // 4. Generate evaluation key
    void* ek = bfv_generate_evaluation_key(ctx, sk);
    assert(ek && "Failed to generate evaluation key");
    printf("4. Evaluation key generated successfully\n");


    // 5. Encode values
    printf("About to encode values, context pointer: %p\n", ctx);
    int64_t values[4] = {10, 20, 30, 40};
    printf("Values array at %p: [%ld, %ld, %ld, %ld]\n", 
           (void*)values, values[0], values[1], values[2], values[3]);

    // Print BFV lib version if available
    // Uncomment if such a function exists
    // printf("BFV library version: %s\n", bfv_version());

    void* pt = bfv_encode_int_array(ctx, values, 4);
    if (!pt) {
        printf("ERROR: bfv_encode_int_array returned NULL\n");
        const char* errMsg = bfv_get_last_error();
        if (errMsg) {
            printf("bfv_get_last_error: %s\n", errMsg);
            bfv_free_string((char*)errMsg);
        }
        // If there's an error logging function, call it here
        // e.g.: printf("Error message: %s\n", bfv_get_last_error());
    }
    assert(pt && "Failed to encode values");

    // 6. Encrypt
    void* ct = bfv_encrypt(pt, sk);
    assert(ct && "Failed to encrypt");
    printf("6. Plaintext encrypted successfully\n");

    // 7. Decrypt
    void* pt2 = bfv_decrypt(ct, sk);
    assert(pt2 && "Failed to decrypt");
    printf("7. Ciphertext decrypted successfully\n");

    // 8. Decode
    int64_t result[4] = {0};
    int32_t actualCount = 0;
    int ok = bfv_decode_to_int_array(pt2, result, 4, &actualCount);
    assert(ok && "Failed to decode");
    assert(actualCount == 4);
    printf("8. Decoded values: [");
    for (int i = 0; i < actualCount; ++i) {
        printf("%ld", result[i]);
        if (i < actualCount - 1) printf(", ");
        assert(result[i] == values[i]);
    }
    printf("] (count: %d)\n", actualCount);

    // 9. Homomorphic add
    void* ct2 = bfv_encrypt(pt, sk);
    void* ct_sum = bfv_add(ct, ct2);
    assert(ct_sum && "Failed to add ciphertexts");
    
    // Verify addition result
    void* pt_sum = bfv_decrypt(ct_sum, sk);
    int64_t sum_result[4] = {0};
    int32_t sum_count = 0;
    bfv_decode_to_int_array(pt_sum, sum_result, 4, &sum_count);
    printf("9. Homomorphic addition result: [");
    for (int i = 0; i < sum_count; ++i) {
        printf("%ld", sum_result[i]);
        if (i < sum_count - 1) printf(", ");
    }
    printf("] (expected: [20, 40, 60, 80])\n");
    bfv_free_plaintext(pt_sum);

    // 10. Homomorphic sub
    void* ct_diff = bfv_sub(ct, ct2);
    assert(ct_diff && "Failed to subtract ciphertexts");
    
    // Verify subtraction result
    void* pt_diff = bfv_decrypt(ct_diff, sk);
    int64_t diff_result[4] = {0};
    int32_t diff_count = 0;
    bfv_decode_to_int_array(pt_diff, diff_result, 4, &diff_count);
    printf("10. Homomorphic subtraction result: [");
    for (int i = 0; i < diff_count; ++i) {
        printf("%ld", diff_result[i]);
        if (i < diff_count - 1) printf(", ");
    }
    printf("] (expected: [0, 0, 0, 0])\n");
    bfv_free_plaintext(pt_diff);

    // 11. Homomorphic multiply
    void* ct_mul = bfv_multiply(ct, ct2, ek);
    assert(ct_mul && "Failed to multiply ciphertexts");
    
    // Verify multiplication result
    void* pt_mul = bfv_decrypt(ct_mul, sk);
    int64_t mul_result[4] = {0};
    int32_t mul_count = 0;
    bfv_decode_to_int_array(pt_mul, mul_result, 4, &mul_count);
    printf("11. Homomorphic multiplication result: [");
    for (int i = 0; i < mul_count; ++i) {
        printf("%ld", mul_result[i]);
        if (i < mul_count - 1) printf(", ");
    }
    printf("] (expected: [100, 400, 900, 1600])\n");
    bfv_free_plaintext(pt_mul);

    // 12. Add plaintext
    void* ct_addpt = bfv_add_plaintext(ct, pt);
    assert(ct_addpt && "Failed to add plaintext to ciphertext");
    
    // Verify plaintext addition result
    void* pt_addpt = bfv_decrypt(ct_addpt, sk);
    int64_t addpt_result[4] = {0};
    int32_t addpt_count = 0;
    bfv_decode_to_int_array(pt_addpt, addpt_result, 4, &addpt_count);
    printf("12. Add plaintext result: [");
    for (int i = 0; i < addpt_count; ++i) {
        printf("%ld", addpt_result[i]);
        if (i < addpt_count - 1) printf(", ");
    }
    printf("] (expected: [20, 40, 60, 80])\n");
    bfv_free_plaintext(pt_addpt);

    // 13. Sub plaintext
    void* ct_subpt = bfv_sub_plaintext(ct, pt);
    assert(ct_subpt && "Failed to subtract plaintext from ciphertext");
    
    // Verify plaintext subtraction result
    void* pt_subpt = bfv_decrypt(ct_subpt, sk);
    int64_t subpt_result[4] = {0};
    int32_t subpt_count = 0;
    bfv_decode_to_int_array(pt_subpt, subpt_result, 4, &subpt_count);
    printf("13. Subtract plaintext result: [");
    for (int i = 0; i < subpt_count; ++i) {
        printf("%ld", subpt_result[i]);
        if (i < subpt_count - 1) printf(", ");
    }
    printf("] (expected: [0, 0, 0, 0])\n");
    bfv_free_plaintext(pt_subpt);

    // 14. Negate
    void* ct_neg = bfv_negate(ct);
    assert(ct_neg && "Failed to negate ciphertext");
    
    // Verify negation result
    void* pt_neg = bfv_decrypt(ct_neg, sk);
    int64_t neg_result[4] = {0};
    int32_t neg_count = 0;
    bfv_decode_to_int_array(pt_neg, neg_result, 4, &neg_count);

        // Post-processing for negative numbers:
int64_t halfMod = 557057 / 2;  // 278528
for (int i = 0; i < neg_count; ++i) {
    if (neg_result[i] > halfMod) {
        neg_result[i] -= 557057;  // subtract the actual modulus
    }
}

    printf("14. Negation result: [");
    for (int i = 0; i < neg_count; ++i) {
        printf("%ld", neg_result[i]);
        if (i < neg_count - 1) printf(", ");
    }
    printf("] (expected: [-10, -20, -30, -40])\n");
    bfv_free_plaintext(pt_neg);

    // 15. Noise budget
//    double noise = bfv_get_noise_budget(ct, sk);
//    printf("15. Noise budget: %.2f bits\n", noise);
//
  //  printf("\n=== Freeing resources ===\n");
    // 17. Free all objects
    bfv_free_parameters(params);
    bfv_free_context(ctx);
    bfv_free_secret_key(sk);
    bfv_free_evaluation_key(ek);
    bfv_free_plaintext(pt);
    bfv_free_ciphertext(ct);
    bfv_free_plaintext(pt2);
    bfv_free_ciphertext(ct2);
    bfv_free_ciphertext(ct_sum);
    bfv_free_ciphertext(ct_diff);
    bfv_free_ciphertext(ct_mul);
    bfv_free_ciphertext(ct_addpt);
    bfv_free_ciphertext(ct_subpt);
    bfv_free_ciphertext(ct_neg);

    printf("\nAll BFV C interface tests passed!\n");
    return 0;
}