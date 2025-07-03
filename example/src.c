#include <stdio.h>
#include <stdlib.h>

int* a;

int test(unsigned int i) {
    // if (i >= 5 && i <= 10) {
    //     return -1;
    // }

    if (i > 10) {
        return -1;
    }
    return a[i];
}

int main() {
    unsigned int i;
    scanf("%u", &i);

    a = malloc(5 * sizeof(int));
    a[0] = 1;
    a[1] = 2;
    a[2] = 3;
    a[3] = 4;
    a[4] = 5;

    int ret = test(i);
    if (ret != -1) {
        printf("Return value: %d\n", ret);
    }

    free(a);
}