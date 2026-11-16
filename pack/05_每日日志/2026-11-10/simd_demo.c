#include <stdint.h>
void add8(int32_t *a, int32_t *b, int32_t *out, int n) {
    for (int i = 0; i < n; i++) out[i] = a[i] + b[i];
}
int sum16(int16_t *v, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += v[i];
    return s;
}
void zero128(int32_t *buf) {
    for (int i = 0; i < 32; i++) buf[i] = 0;
}
