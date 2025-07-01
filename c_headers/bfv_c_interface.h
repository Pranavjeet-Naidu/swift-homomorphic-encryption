#ifndef BFV_C_INTERFACE_H
#define BFV_C_INTERFACE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* bfv_value_t;

bfv_value_t bfv_create_value(int64_t val);
int64_t bfv_add_values(bfv_value_t lhs, bfv_value_t rhs);
void bfv_free_value(bfv_value_t val);

#ifdef __cplusplus
}
#endif

#endif // BFV_C_INTERFACE_H