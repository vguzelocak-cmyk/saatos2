/* Windows x64 __chkstk: probe the caller's prospective stack, preserving RAX/RCX. */
.text
.globl driverlab_chkstk
.type driverlab_chkstk, @function
driverlab_chkstk:
    pushq %rcx
    pushq %rax
    leaq 24(%rsp), %rcx
    cmpq $4096, %rax
    jb .Lfinal
.Lpage:
    subq $4096, %rcx
    testb $0, (%rcx)
    subq $4096, %rax
    cmpq $4096, %rax
    jae .Lpage
.Lfinal:
    subq %rax, %rcx
    testb $0, (%rcx)
    popq %rax
    popq %rcx
    ret
.size driverlab_chkstk, .-driverlab_chkstk
.section .note.GNU-stack,"",@progbits
