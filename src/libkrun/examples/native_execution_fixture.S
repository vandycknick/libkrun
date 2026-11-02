/* Diagnostic-only reset-PIT CPU fixture, not the production Linux profile.
 * Link at 0x1000; every sentinel is seeded only before the first guest loop.
 * Shared slot layout is defined by native_execution_probe.rs. */
.section .text
.global _start
.code16
_start:
    cli
    xor %ax,%ax
    mov %ax,%ds
    mov %ax,%es
    mov %ax,%ss
    lgdt gdt_pointer
    mov %cr0,%eax
    or $1,%eax
    mov %eax,%cr0
    ljmpl $8,$protected
.code32
protected:
    mov $16,%ax
    mov %ax,%ds
    mov %ax,%es
    mov %ax,%ss
    mov $0x8000,%eax
    mov %eax,%cr3
    mov %cr4,%eax
    or $0x620,%eax
    mov %eax,%cr4
    mov $0xc0000080,%ecx
    rdmsr
    or $0x100,%eax
    wrmsr
    mov %cr0,%eax
    and $0xfffffffb,%eax
    or $0x80000002,%eax
    mov %eax,%cr0
    ljmpl $24,$long_mode
.code64
long_mode:
    mov $1,%eax
    cpuid
    shr $24,%ebx
    mov %ebx,%ebp
    shl $12,%rbp
    add $0x100000,%rbp
    lea 0x80000(%rbp),%rsp
    movq $0x53494c4f,0(%rbp)
    incq 8(%rbp)
    lidt idt_pointer
    mov $0x1b,%ecx
    rdmsr
    or $0xc00,%eax
    wrmsr
    mov $0x80f,%ecx
    mov $0x1ff,%eax
    xor %edx,%edx
    wrmsr
    mov $0x832,%ecx
    mov $0x400e0,%eax
    wrmsr
    /* x87, SSE and (when exposed) AVX stay live across every host cut. */
    fninit
    fld1
    movdqu sentinel(%rip),%xmm15
    mov $1,%eax
    cpuid
    bt $26,%ecx
    jnc no_avx
    bt $28,%ecx
    jnc no_avx
    mov %cr4,%rax
    or $0x40000,%rax
    mov %rax,%cr4
    xor %ecx,%ecx
    xor %edx,%edx
    mov $7,%eax
    xsetbv
    vmovdqu sentinel(%rip),%ymm14
    movq $1,128(%rbp)
no_avx:
    movabs $0x13579bdf2468ace0,%r12
    movabs $0xfedcba9876543210,%r13
    sti
loop:
    incq 16(%rbp)
    movabs $0x13579bdf2468ace0,%rax
    cmp %rax,%r12
    jne failure
    movabs $0xfedcba9876543210,%rax
    cmp %rax,%r13
    jne failure
    movdqu %xmm15,160(%rbp)
    mov sentinel(%rip),%rax
    cmp %rax,160(%rbp)
    jne failure
    mov sentinel+8(%rip),%rax
    cmp %rax,168(%rbp)
    jne failure
    cmpq $0,128(%rbp)
    je checked
    vmovdqu %ymm14,192(%rbp)
    mov sentinel+16(%rip),%rax
    cmp %rax,208(%rbp)
    jne failure
    mov sentinel+24(%rip),%rax
    cmp %rax,216(%rbp)
    jne failure
checked:
    fstl 224(%rbp)
    movabs $0x3ff0000000000000,%rax
    cmp %rax,224(%rbp)
    jne failure
    mov 80(%rbp),%rax
    cmp 88(%rbp),%rax
    je command
    mov %rax,%r11
    lfence
    rdtsc
    shl $32,%rdx
    or %rdx,%rax
    mov %rax,96(%rbp)
    mov %r11,88(%rbp)
command:
    mov 32(%rbp),%r10
    test %r10,%r10
    jnz nonzero_command
    cmpq $13,40(%rbp)
    jne idle
    mov $0x6e0,%ecx
    xor %eax,%eax
    xor %edx,%edx
    wrmsr
idle:
    movq $0,40(%rbp)
    movq $0,144(%rbp)
    movq $0,152(%rbp)
    sti
    jmp loop
nonzero_command:
    cmp $13,%r10
    je steady
    cmp $11,%r10
    je active_pit
    cmp $12,%r10
    je count_mode
    cmp $6,%r10
    je io
    cmp $7,%r10
    je mmio
    cmp $8,%r10
    je start_ap
    cmp $9,%r10
    je unmask
    cmp $5,%r10
    je in_service
    /* Host supplies ticks per 500 ms from actual GET_TSC_KHZ. */
    cmp 40(%rbp),%r10
    je waiting
    cmp $1,%r10
    je interrupts_enabled
    cli
interrupts_enabled:
    mov $0x832,%ecx
    mov $0x400e0,%eax
    cmp $3,%r10
    jne lvt_ready
    or $0x10000,%eax
lvt_ready:
    xor %edx,%edx
    wrmsr
    rdtsc
    shl $32,%rdx
    or %rdx,%rax
    add 136(%rbp),%rax
    mov %rax,64(%rbp)
    mov %rax,%rdx
    shr $32,%rdx
    mov $0x6e0,%ecx
    wrmsr
    incq 56(%rbp)
    mov %r10,40(%rbp)
    cmp $10,%r10
    je io
waiting:
    cmp $1,%r10
    je halted
    lfence
    rdtsc
    shl $32,%rdx
    or %rdx,%rax
    cmp 64(%rbp),%rax
    jb loop
    cmp $2,%r10
    jne expired
    mov $0x827,%ecx
    rdmsr
    test $1,%eax
    jz loop
expired:
    cmpq $2,144(%rbp)
    je loop
    movq $1,144(%rbp)
    cmp $4,%r10
    jne loop
    mov $0x827,%ecx
    rdmsr
    test $1,%eax
    jz loop
    rdtsc
    shl $32,%rdx
    or %rdx,%rax
    add 136(%rbp),%rax
    mov %rax,64(%rbp)
    mov %rax,%rdx
    shr $32,%rdx
    mov $0x6e0,%ecx
    wrmsr
    incq 56(%rbp)
    movq $2,144(%rbp)
    jmp loop
halted:
    hlt
    cmpq $13,32(%rbp)
    je steady_io
    movq $0,32(%rbp)
    jmp loop
in_service:
    cmp 40(%rbp),%r10
    je halted
    mov %r10,40(%rbp)
    rdtsc
    shl $32,%rdx
    or %rdx,%rax
    add 136(%rbp),%rax
    mov %rax,64(%rbp)
    mov %rax,%rdx
    shr $32,%rdx
    mov $0x6e0,%ecx
    wrmsr
    incq 56(%rbp)
    jmp halted
unmask:
    mov $0x832,%ecx
    mov $0x400e0,%eax
    xor %edx,%edx
    wrmsr
    movq $0,32(%rbp)
    sti
    jmp loop
io:
    mov $0x500,%dx
    in %dx,%al
.global io_complete
io_complete:
    cmp $0xa5,%al
    jne failure
    incq 104(%rbp)
    movq $0,32(%rbp)
    jmp loop
mmio:
    movabs $0x300000,%rax
    mov (%rax),%al
.global mmio_complete
mmio_complete:
    cmp $0x5a,%al
    jne failure
    incq 112(%rbp)
    movq $0,32(%rbp)
    jmp loop
start_ap:
    mov $0x830,%ecx
    mov $0x0000c500,%eax
    mov $1,%edx
    wrmsr
    mov 136(%rbp),%rax
    xor %edx,%edx
    mov $50,%ecx
    div %rcx
    mov %rax,%r11
    rdtsc
    shl $32,%rdx
    or %rdx,%rax
    add %rax,%r11
init_settle:
    pause
    rdtsc
    shl $32,%rdx
    or %rdx,%rax
    cmp %r11,%rax
    jb init_settle
    mov $0x830,%ecx
    mov $0x00000601,%eax
    mov $1,%edx
    wrmsr
    movq $0,32(%rbp)
    jmp loop
failure:
    incq 24(%rbp)
    cli
    hlt
    jmp failure
.balign 16
sentinel:
    .quad 0x0123456789abcdef,0xfedcba9876543210
    .quad 0x1122334455667788,0x8877665544332211
active_pit:
    cmpq $11,40(%rbp)
    je loop
    mov $0x34,%al
    out %al,$0x43
    mov $0xff,%al
    out %al,$0x40
    out %al,$0x40
    movq $11,40(%rbp)
    jmp loop
count_mode:
    cmpq $12,40(%rbp)
    je loop
    mov $0x832,%ecx
    mov $0x300e0,%eax
    xor %edx,%edx
    wrmsr
    mov $0x838,%ecx
    mov $0x1000000,%eax
    wrmsr
    movq $12,40(%rbp)
    jmp loop
steady:
    cmpq $13,40(%rbp)
    je halted
    mov $0x832,%ecx
    mov $0x400e0,%eax
    xor %edx,%edx
    wrmsr
    call arm_steady
    movq $13,40(%rbp)
    jmp halted
steady_io:
    mov $0x500,%dx
    in %dx,%al
    cmp $0xa5,%al
    jne failure
    incq 104(%rbp)
    movabs $0x300000,%rax
    mov (%rax),%al
    cmp $0x5a,%al
    jne failure
    incq 112(%rbp)
    jmp loop
arm_steady:
    push %r11
    mov 136(%rbp),%rax
    xor %edx,%edx
    mov $50,%ecx
    div %rcx
    mov %rax,%r11
    rdtsc
    shl $32,%rdx
    or %rdx,%rax
    add %r11,%rax
    mov %rax,%rdx
    shr $32,%rdx
    mov $0x6e0,%ecx
    wrmsr
    incq 56(%rbp)
    pop %r11
    ret
.global interrupt
interrupt:
    push %rax
    push %rcx
    push %rdx
    incq 48(%rbp)
    cmpq $13,32(%rbp)
    jne service
    call arm_steady
    jmp eoi
service:
    cmpq $5,32(%rbp)
    jne eoi
    movq $1,152(%rbp)
service_wait:
    cmpq $5,32(%rbp)
    je service_wait
eoi:
    mov $0x80b,%ecx
    xor %eax,%eax
    xor %edx,%edx
    wrmsr
    pop %rdx
    pop %rcx
    pop %rax
    iretq
.balign 8
gdt:
    .quad 0,0x00cf9a000000ffff,0x00cf92000000ffff,0x00af9a000000ffff
gdt_pointer:
    .word 31
    .long gdt
idt_pointer:
    .word 4095
    .quad 0xb000
/* The controller fills the interrupt gate from the ELF symbol map. */
.org 0x7000
    .quad 0x9003
    .fill 511,8,0
    .quad 0xa003
    .fill 511,8,0
    .quad 0x83,0x200083
    .fill 510,8,0
.org 0xb000
