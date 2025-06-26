/*
Insert if-return meta-program example

Insert new if-return statement to the original function.
`__meta_patch_id` is used to select the patch. Set `META_PATCH_ID` environment variable to select the patch.
If `META_PATCH_ID` is not set or set to 0, the original function is used.

To check the patch is reached, set `META_REACHED_FILE` environment variable to the file name.
If the patch is reached, the file is created.
Make sure the file is removed before running the program again.
*/
#include <stdio.h>
#include <stdlib.h>

// meta-program header
#include <stdlib.h>
#include <stdint.h>
int __meta_patch_id = -1;
void __meta_patch(uint32_t int_count, int64_t *int_array,
                  uint32_t uint_count, uint64_t *uint_array,
                  uint32_t ptr_count, void** ptr_array) {
    char* file_name = getenv("META_REACHED_FILE");
    if (file_name) {
        FILE* file = fopen(file_name, "w");
        for (uint32_t i = 0; i < int_count; i++) {
            fprintf(file, "%lld ", int_array[i]);
        }
        for (uint32_t i = 0; i < uint_count; i++) {
            fprintf(file, "%llu ", uint_array[i]);
        }
        for (uint32_t i = 0; i < ptr_count; i++) {
            fprintf(file, "%d ", ptr_array[i] == NULL ? 0 : 1);
        }

        fclose(file);
    }
    return;
}
int __meta_condition;
// end meta-program header

int *a;

int test(unsigned int i, unsigned int j) {
    // meta-program
    if (__meta_patch_id == -1) __meta_patch_id = getenv("META_PATCH_ID") ? atoi(getenv("META_PATCH_ID")) : 0;
    __meta_patch(2, (int64_t[]){(int64_t)i, (int64_t)j}, 0, (uint64_t[]){}, 1, (void*[]){(void*)a}); // Call meta patch function to indicate the patch is reached
    switch (__meta_patch_id) {
        case 1: // Correct patch
            if (i >= 5) {
                return -1;
            }
            break;
        case 2: // Incorrect patch
            if (i >= 5 || a[5] > 5) {
                return -1;
            }
            break;
    }
    // end meta-program

    if (i > 10) {
        return -1;
    }
    if (j > 100)
      return -1;
    if (i > j)
      return -1;
    if (j < 0)
      return -1;
    return a[i];
}

int main() {
    unsigned int i, j;
    scanf("%u %u", &i, &j);

    a = (int[]){1, 2, 3, 4, 5}; // Initialize array with values
    int ret = test(i, j);
    if (ret != -1) {
        printf("Return value: %d\n", ret);
    }
}