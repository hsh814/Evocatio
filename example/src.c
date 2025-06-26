#include <stdio.h>
#include <stdlib.h>

int* a;

int test(unsigned int i) {
    // if (i >= 5) {
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

    a = (int[]){1, 2, 3, 4, 5}; // Initialize array with values
    int ret = test(i);
    if (ret != -1) {
        printf("Return value: %d\n", ret);
    }
}