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
#define PAC_SHM_MAX_SIZE 4096
int __meta_patch_id = -1;
int __meta_condition;

void __meta_write(uint32_t type, void *data) {
    
    char *pac_reached_env = getenv("PAC_REACHED_ENV");
    static void *shm_addr = NULL;
    static int shm_id = -1;
    static size_t shm_offset = 0;
    FILE *file = NULL;

    // 1. shared memory
    if (pac_reached_env) {
        shm_id = atoi(pac_reached_env);
        if (shm_id > 0 && shm_addr == NULL) {
            shm_addr = shmat(shm_id, NULL, 0);
            if (shm_addr == (void *)-1) {
                fprintf(stderr, "Error: Failed to attach to shared memory\n");
                shm_addr = NULL;
                return;
            }
        }
        if (shm_addr) {
            if (shm_offset + 8 > PAC_SHM_MAX_SIZE) return;
            if (type == 0) { // total size
                memcpy(shm_addr + shm_offset, data, sizeof(uint64_t));
                shm_offset += sizeof(uint64_t);
            } else if (type == 1) { // int64_t
                memcpy(shm_addr + shm_offset, data, sizeof(int64_t));
                shm_offset += sizeof(int64_t);
            } else if (type == 2) { // uint64_t
                memcpy(shm_addr + shm_offset, data, sizeof(uint64_t));
                shm_offset += sizeof(uint64_t);
            } else if (type == 3) { // void*
                memcpy(shm_addr + shm_offset, data, sizeof(void*));
                shm_offset += sizeof(void*);
            } else if (type == 4) { // branch
                memcpy(shm_addr + shm_offset, data, sizeof(uint64_t));
                shm_offset += sizeof(uint64_t);
            }
            return;
        }
    }

    // 2. fallback to file
    char *file_name = getenv("PAC_REACHED_FILE_NAME");
    if (file_name) {
        file = fopen(file_name, "a");
        if (!file) return;
        if (type == 0) {
            fprintf(file, "%lld ", *(uint64_t*)data);
        } else if (type == 1) {
            fprintf(file, "%lld ", *(int64_t*)data);
        } else if (type == 1) {
            fprintf(file, "%llu ", *(uint64_t*)data);
        } else if (type == 3) {
            fprintf(file, "%p ", *(void**)data);
        } else if (type == 4) {
            fprintf(file, "%lld\n", *(int64_t*)data);
        }
        fclose(file);
        return;
    }
}

void __meta_patch(uint32_t int_count, int64_t *int_array,
                  uint32_t uint_count, uint64_t *uint_array,
                  uint32_t ptr_count, void** ptr_array) {
    uint64_t tmp;
    tmp = (uint64_t)(int_count + uint_count + ptr_count + 1);
    __meta_write(0, (void*)&tmp);
    for (uint32_t i = 0; i < int_count; i++) {
        __meta_write(1, (void*)&int_array[i]);
    }
    for (uint32_t i = 0; i < uint_count; i++) {
        __meta_write(2, (void*)&uint_array[i]);
    }
    for (uint32_t i = 0; i < ptr_count; i++) {
        __meta_write(3, (void*)&ptr_array[i]);
    }
    tmp = (uint64_t)__meta_condition;
    __meta_write(4, (void*)&tmp);
}
// end meta-program header

int *a;

int test(unsigned int i) {
    // meta-program
    if (__meta_patch_id == -1) __meta_patch_id = getenv("META_PATCH_ID") ? atoi(getenv("META_PATCH_ID")) : 0;
    switch (__meta_patch_id) {
        case 1: // Correct patch: fuzzer will terminate after max unique program state reached
            __meta_condition = (i >= 5 && i <= 10);
            break;
        case 2: // Incorrect patch: fuzzer will terminate with regression error (failes patched program, but passes buggy program)
            __meta_condition = (i >= 5 && a[5] > 5);
            break;
        case 3: // Semantically equivalent, but overfitted patch: fuzzer will terminate with regression error (different branch executed)
            __meta_condition = i >= 5;
            break;
        default:
            __meta_condition = 0;
    }
    __meta_patch(1, (int64_t[]){(int64_t)i}, 0, (uint64_t[]){}, 1, (void*[]){(void*)a}); // Call meta patch function to indicate the patch is reached
    // end meta-program

    if (__meta_condition) {
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