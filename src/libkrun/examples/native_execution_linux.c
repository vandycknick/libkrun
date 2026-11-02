/* Userspace workload for the separately required ordinary production Linux gate.
 * Never resets live sentinels after startup. Pin one worker to each online CPU.
 * Build explicitly: cc -O2 -pthread -static -o native-execution-linux this-file.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct worker { unsigned cpu; atomic_uint_fast64_t progress; atomic_int failed; };

#if defined(__x86_64__)
/* Static musl fixtures must not depend on a compiler's CPU-model runtime. */
static int avx_enabled(void) {
    uint32_t eax = 1, ebx, ecx = 0, edx;
    __asm__ volatile ("cpuid"
        : "+a" (eax), "=b" (ebx), "+c" (ecx), "=d" (edx));
    const uint32_t required = (UINT32_C(1) << 26) | (UINT32_C(1) << 27) | (UINT32_C(1) << 28);
    if ((ecx & required) != required) return 0;
    __asm__ volatile ("xgetbv" : "=a" (eax), "=d" (edx) : "c" (0));
    uint64_t xcr0 = (uint64_t)edx << 32 | eax;
    return (xcr0 & UINT64_C(7)) == UINT64_C(7);
}

static void *run(void *opaque) {
    struct worker *worker = opaque;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(worker->cpu, &set);
    int error = pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
    if (error) { atomic_store(&worker->failed, error); return NULL; }
    /* No libc call in the loop may spill/reseed the live guest register values. */
    uint64_t count = 0;
    int failed = 0;
    uint64_t fp;
    int avx = avx_enabled();
    __asm__ volatile (
        "movabs $0x13579bdf2468ace0, %%r12\n"
        "movabs $0xfedcba9876543210, %%r13\n"
        "pcmpeqd %%xmm15, %%xmm15\n"
        "test %[avx], %[avx]\n"
        "jz 3f\n"
        "vpcmpeqd %%ymm14, %%ymm14, %%ymm14\n"
        "3:\n"
        "fld1\n"
        "1:\n"
        "movabs $0x13579bdf2468ace0, %%rax\n"
        "cmp %%rax, %%r12\n"
        "jne 2f\n"
        "movabs $0xfedcba9876543210, %%rax\n"
        "cmp %%rax, %%r13\n"
        "jne 2f\n"
        "pmovmskb %%xmm15, %%eax\n"
        "cmp $65535, %%eax\n"
        "jne 2f\n"
        "fstl %[fp]\n"
        "movabs $0x3ff0000000000000, %%rax\n"
        "cmp %[fp], %%rax\n"
        "jne 2f\n"
        "test %[avx], %[avx]\n"
        "jz 4f\n"
        "vextractf128 $1, %%ymm14, %%xmm0\n"
        "pmovmskb %%xmm0, %%eax\n"
        "cmp $65535, %%eax\n"
        "jne 2f\n"
        "4:\n"
        "inc %[count]\n"
        "mov %[count], (%[progress])\n"
        "jmp 1b\n"
        "2: mov $1, %[failed]\n"
        "fstp %%st(0)\n"
        : [count] "+&r" (count), [failed] "+&r" (failed), [fp] "=m" (fp)
        : [progress] "r" (&worker->progress), [avx] "r" (avx)
        : "rax", "r12", "r13", "xmm0", "xmm14", "xmm15", "cc", "memory");
    atomic_store(&worker->failed, failed);
    return NULL;
}
#else
#error Actual KVM arm64 and HVF workload implementation and runtime are pending owner lane; never infer from x86.
#endif

int main(void) {
    cpu_set_t online;
    if (sched_getaffinity(0, sizeof(online), &online)) { perror("sched_getaffinity"); return 1; }
    unsigned count = CPU_COUNT(&online);
    if (!count || count > 255) { fprintf(stderr, "unsupported CPU count %u\n", count); return 1; }
    struct worker *workers = calloc(count, sizeof(*workers));
    pthread_t *threads = calloc(count, sizeof(*threads));
    if (!workers || !threads) { perror("calloc"); free(workers); free(threads); return 1; }
    unsigned index = 0;
    for (unsigned cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (!CPU_ISSET(cpu, &online)) continue;
        workers[index].cpu = cpu;
        int error = pthread_create(&threads[index], NULL, run, &workers[index]);
        if (error) { fprintf(stderr, "pthread_create: %s\n", strerror(error)); return 1; }
        ++index;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    uint64_t sequence = 0;
    for (;;) {
        struct timespec mono, boot;
        if (clock_gettime(CLOCK_MONOTONIC, &mono) || clock_gettime(CLOCK_BOOTTIME, &boot)) { perror("clock_gettime"); return 1; }
        printf("{\"schema\":1,\"fixture\":\"production-linux-live-registers\",\"pid\":%ld,\"sequence\":%" PRIu64 ",\"monotonic_ns\":%" PRIu64 ",\"boottime_ns\":%" PRIu64 ",\"cpus\":[", (long)getpid(), ++sequence,
            (uint64_t)mono.tv_sec * UINT64_C(1000000000) + mono.tv_nsec,
            (uint64_t)boot.tv_sec * UINT64_C(1000000000) + boot.tv_nsec);
        for (unsigned cpu = 0; cpu < count; ++cpu) {
            int failed = atomic_load(&workers[cpu].failed);
            printf("%s{\"cpu\":%u,\"progress\":%" PRIuFAST64 ",\"failed\":%d}", cpu ? "," : "", workers[cpu].cpu, atomic_load(&workers[cpu].progress), failed);
            if (failed) return 1;
        }
        puts("]}");
        struct timespec wait = { .tv_sec = 0, .tv_nsec = 100000000 };
        while (nanosleep(&wait, &wait) && errno == EINTR) {}
    }
}
