/* Explicit standalone source fixture, linked at 0x1c001000. Linux retains
 * CPUs 0/1 and the ordinary kernel. Only source construction starts CPU 2;
 * CPU 3 is started by this guest's actual INIT/SIPI, never a restore setter. */
.section .text
.code64
.global _start, witness_interrupt, witness_io_complete, witness_mmio_complete
_start:
    cli
    mov $0x1c010000,%rbp
    mov $0x1c020000,%rsp
    lidt idt_pointer(%rip)
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
    fninit
    fld1
    pcmpeqd %xmm15,%xmm15
    mov $1,%eax
    cpuid
    bt $26,%ecx
    jnc seeded
    bt $28,%ecx
    jnc seeded
    mov %cr4,%rax
    or $0x40000,%rax
    mov %rax,%cr4
    xor %ecx,%ecx
    xor %edx,%edx
    mov $7,%eax
    xsetbv
    pcmpeqd %xmm14,%xmm14
    vinsertf128 $1,%xmm14,%ymm14,%ymm14
    movq $1,168(%rbp)
seeded:
    movabs $0x13579bdf2468ace0,%r12
    movabs $0xfedcba9876543210,%r13
    movq $0x53494c4f,0(%rbp)
    incq 8(%rbp)
loop:
    cmpq $4,24(%rbp)
    je sample_lvt
    cmpq $13,24(%rbp)
    jne progress
sample_lvt:
    mov $0x832,%ecx
    rdmsr
    mov %rax,176(%rbp)
progress:
    incq 16(%rbp)
    mov 112(%rbp),%r11
    cmp 120(%rbp),%r11
    je dispatch
    lfence
    rdtsc
    shl $32,%rdx
    or %rdx,%rax
    mov %rax,128(%rbp)
    mov %r11,120(%rbp)
dispatch:
    mov 24(%rbp),%r10
    cmp 32(%rbp),%r10
    je waiting
    cmp $9,%r10
    je start_ap
    cmp $10,%r10
    je unmask
    cmp $11,%r10
    je accept
    cmp $12,%r10
    je reset
    cmp $7,%r10
    je io
    cmp $8,%r10
    je mmio
    test %r10,%r10
    jz loop
    cli
    movq $0,64(%rbp)
    movq $0,88(%rbp)
    mov $0x832,%ecx
    mov $0x400e0,%eax
    cmp $4,%r10
    je mask_lvt
    cmp $13,%r10
    jne set_lvt
mask_lvt:
    or $0x10000,%eax
set_lvt:
    xor %edx,%edx
    wrmsr
    rdtsc
    shl $32,%rdx
    or %rdx,%rax
    mov 80(%rbp),%rdi
    imul $500,%rdi,%rdi
    add %rdi,%rax
    mov %rax,56(%rbp)
    mov %rax,%rdx
    shr $32,%rdx
    mov $0x6e0,%ecx
    wrmsr
    incq 48(%rbp)
    mov %r10,32(%rbp)
    cmp $3,%r10
    je due_io
    cmp $1,%r10
    je halt
    cmp $6,%r10
    jne waiting
    movq $1,88(%rbp)
    sti
halt:
    sti
    hlt
    cmpq $1,24(%rbp)
    jne loop
    movq $0,24(%rbp)
    movq $0,32(%rbp)
    jmp loop
waiting:
    cmp $1,%r10
    je halt
    cmp $6,%r10
    je loop
    cmp $2,%r10
    jb loop
    cmp $5,%r10
    ja loop
    lfence
    rdtsc
    shl $32,%rdx
    or %rdx,%rax
    cmp 56(%rbp),%rax
    jb loop
    cmpq $0,64(%rbp)
    jne loop
    cmp $3,%r10
    je due_io
    cmp $4,%r10
    je expired
    mov $0x827,%ecx
    rdmsr
    test $1,%eax
    jz loop
    cmp $5,%r10
    jne expired
    rdtsc
    shl $32,%rdx
    or %rdx,%rax
    mov 80(%rbp),%rdi
    imul $500,%rdi,%rdi
    add %rdi,%rax
    mov %rax,56(%rbp)
    mov %rax,%rdx
    shr $32,%rdx
    mov $0x6e0,%ecx
    wrmsr
    incq 48(%rbp)
expired:
    movq $1,64(%rbp)
    jmp loop
due_io:
    movq $1,64(%rbp)
    mov 136(%rbp),%rax
    movl $0x5a,0x30(%rax)
    jmp loop
io:
    mov $0x3ef,%dx
    mov $0x5a,%al
    out %al,%dx
witness_io_complete:
    incq 96(%rbp)
    mov %r10,32(%rbp)
    jmp loop
mmio:
    mov 136(%rbp),%rax
    movl $0x5a,0x30(%rax)
witness_mmio_complete:
    incq 104(%rbp)
    mov %r10,32(%rbp)
    jmp loop
unmask:
    mov $0x832,%ecx
    mov $0x400e0,%eax
    xor %edx,%edx
    wrmsr
accept:
    movq $0,88(%rbp)
    mov %r10,32(%rbp)
    sti
    jmp loop
reset:
    cli
    mov $0x6e0,%ecx
    xor %eax,%eax
    xor %edx,%edx
    wrmsr
    mov $0x832,%ecx
    mov $0x400e0,%eax
    wrmsr
    movq $0,64(%rbp)
    mov %r10,32(%rbp)
    sti
    jmp loop
start_ap:
    mov $0x830,%ecx
    mov $3,%edx
    mov $0xc500,%eax
    wrmsr
    mov 80(%rbp),%r11
    imul $10,%r11,%r11
    rdtsc
    shl $32,%rdx
    or %rdx,%rax
    add %rax,%r11
init_wait:
    pause
    rdtsc
    shl $32,%rdx
    or %rdx,%rax
    cmp %r11,%rax
    jb init_wait
    mov $0x830,%ecx
    mov $3,%edx
    mov $0x0670,%eax
    wrmsr
    mov %r10,32(%rbp)
    jmp loop
witness_interrupt:
    push %rax
    push %rcx
    push %rdx
    # Timestamp the actual entry before publishing any observation metadata.
    lfence
    rdtsc
    shl $32,%rdx
    or %rdx,%rax
    mov %rax,%rcx
    # One guest writer; x86 store ordering brackets the published IRQ record.
    incq 184(%rbp)
    mov 144(%rbp),%rax
    mov %rax,152(%rbp)
    mov %rcx,144(%rbp)
    incq 40(%rbp)
    incq 184(%rbp)
    cmpq $0,88(%rbp)
    je eoi
    movq $1,64(%rbp)
service_wait:
    cmpq $11,24(%rbp)
    jne service_wait
    movq $11,32(%rbp)
    movq $0,88(%rbp)
eoi:
    mov $0x80b,%ecx
    xor %eax,%eax
    xor %edx,%edx
    wrmsr
    incq 160(%rbp)
    pop %rdx
    pop %rcx
    pop %rax
    iretq
.balign 16
.global witness_idt
witness_idt:
    .zero 225*16
idt_end:
idt_pointer:
    .word idt_end-witness_idt-1
    .quad witness_idt
