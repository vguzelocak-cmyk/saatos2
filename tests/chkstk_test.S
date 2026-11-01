.text
.globl driverlab_test_chkstk
.type driverlab_test_chkstk, @function
/* SysV args: RDI=probe address, RSI=allocation size. */
driverlab_test_chkstk:
    pushq %rsi
    movq %rdi, %r11
    movq %rsi, %rax
    movabsq $0x123456789abcdef0, %rcx
    call *%r11
    movabsq $0x123456789abcdef0, %rdx
    cmpq %rdx, %rcx
    jne .Lbad
    cmpq (%rsp), %rax
    jne .Lbad
    movl $1, %eax
    popq %rsi
    ret
.Lbad:
    xorl %eax, %eax
    popq %rsi
    ret
.size driverlab_test_chkstk, .-driverlab_test_chkstk
.section .note.GNU-stack,"",@progbits
