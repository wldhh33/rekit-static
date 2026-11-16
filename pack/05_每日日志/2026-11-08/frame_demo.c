#include <stdio.h>

int add8(int a, int b, int c, int d, int e, int f, int g, int h) {
    int s = a + b + c + d + e + f + g + h;
    return s;
}

int main(void) {
    int r = add8(1, 2, 3, 4, 5, 6, 7, 8);
    printf("%d\n", r);
    return 0;
}
