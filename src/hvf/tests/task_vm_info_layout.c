#include <mach/task_info.h>
#include <stddef.h>
#include <stdio.h>

int main(void) {
    printf("full_size=%zu\n", sizeof(task_vm_info_data_t));
    printf("full_count=%u\n", TASK_VM_INFO_COUNT);
    printf("rev1_count=%u\n", TASK_VM_INFO_REV1_COUNT);
    printf("resident_offset=%zu\n", offsetof(task_vm_info_data_t, resident_size));
    printf("reusable_offset=%zu\n", offsetof(task_vm_info_data_t, reusable));
    printf("footprint_offset=%zu\n", offsetof(task_vm_info_data_t, phys_footprint));
    return 0;
}
