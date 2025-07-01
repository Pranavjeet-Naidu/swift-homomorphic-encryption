#include "bfv_c_interface.h"
#include <iostream>

int main() {
    bfv_value_t a = bfv_create_value(42);
    bfv_value_t b = bfv_create_value(58);
    int64_t result = bfv_add_values(a, b);
    std::cout << "Result: " << result << std::endl; // Should print 100
    bfv_free_value(a);
    bfv_free_value(b);
    return 0;
}