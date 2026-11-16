#include <stdint.h>
void add_fixed(int32_t a[128], int32_t b[128], int32_t out[128]) {
    for (int i = 0; i < 128; i++) out[i] = a[i] + b[i];
}
