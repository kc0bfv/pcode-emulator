#include <stdio.h>

#define ADD_OUT_FLAGS(out_var, inval1, inval2) asm ( \
    "add %[invalc], %[invald];" \
    "pushfq;" \
    "pop %[outval];"\
    : [outval] "=r" (out_var) \
    : [invalc] "r" (inval1), [invald] "r" (inval2) \
)

#define SUB_OUT_FLAGS(out_var, inval1, inval2) asm ( \
    "sub %[invald], %[invalc];" \
    "pushfq;" \
    "pop %[outval];"\
    : [outval] "=r" (out_var) \
    : [invalc] "r" (inval1), [invald] "r" (inval2) \
)


long int simple_adds(int inval) {
    return inval + inval;
}

int big_sub(int inval) {
    return inval - 0x7fffffff;
}

long int another_sub(long int inval1, long int inval2) {
    return inval1 - inval2;
}

long int investigate_add_flags(int invala, int invalb) {
    long int retval = 0;
    ADD_OUT_FLAGS(retval, invala, invalb);
    return retval;
}

long int investigate_sub_flags(int invala, int invalb) {
    long int retval = 0;
    SUB_OUT_FLAGS(retval, invala, invalb);
    return retval;
}

long int div(long int invala, long int invalb) {
    return invala / invalb;
}

unsigned long int unsign_div(unsigned long int invala,
        unsigned long int invalb) {
    return invala / invalb;
}

long int sub_if(int inval) {
    if( inval - 1 > 0 ) {
        return 0;
    } else {
        return 1;
    }
}

long unsigned int read_rip() {
    long unsigned int retval = 0;
    asm (
        "lea (%%rip), %[outval];"
        : [outval] "=r" (retval)
    );
    return retval;
}

long unsigned int update_many_regs(long int inval) {
    long unsigned int temp_retval = 0, retval = 0;
    asm (
        "mov %[inval], %%rax;"
        "mov %%rax, %%rbx;"
        "mov %%rbx, %%rcx;"
        "mov %%rcx, %%rdx;"
        "mov %%rdi, %%rsi;"
        "mov %%rsi, %%rdi;"
        "mov %%rdi, %[temp_retval];"
        : [temp_retval] "=r" (temp_retval)
        : [inval] "r" (inval)
        : "cc", "rax", "rbx", "rcx", "rdx", "rsi", "rdi"
    );
    asm (
        "mov %[temp_retval], %%r8;"
        "mov %%r8, %%r9;"
        "mov %%r9, %%r10;"
        "mov %%r10, %%r11;"
        "mov %%r11, %%r12;"
        "mov %%r12, %%r13;"
        "mov %%r13, %%r14;"
        "mov %%r14, %%r15;"
        "mov %%r15, %[retval];"
        : [retval] "=r" (retval)
        : [temp_retval] "r" (temp_retval)
        : "cc", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    );
    return retval;
}

void try_print_simple_adds(int val) {
    printf("Simple adds %x result %lx\n", val, simple_adds(val));
}

int main(int argc, char * argv[] ) {
    try_print_simple_adds(0x10001000);
    try_print_simple_adds(0x20002000);
    try_print_simple_adds(0x60006000);
    try_print_simple_adds(0x80008000);
    try_print_simple_adds(0xd000d000);
    printf("Update many regs result 0x%lx\n", update_many_regs(argc));
    printf("RIP value 0x%lx\n", read_rip());
    
    printf("Another sub 0x%lx\n", another_sub(0x10, 0x40));

    int test_val = 0x7fffffff;
    // With adding - when overflowing signed you get "overflow" set.  When overflowing unsigned you get "carry" set.  Overflow matters with signed add, carry with unsigned.
    // If you're adding signed 0xffffffff twice, you get carry set, but that doesn't matter because it's not helpful for signed add operations.  If it was an unsigned add instead, you'd still get carry set and it would matter, because then you added too large.  Overflow isn't set with this add.  Overflow matters for signed, carry for unsigned add.
    // If you add 0x7fffffff twice you get overflow bit set and carry unset.  If it was a signed add, overflow matters.
    // Ghidra uses INT_CARRY to determine CF in an add, and INT_SCARRY to determine OF in an add.
    // 
    printf("Investigate add flags 0x%x 0x%lx\n", test_val, investigate_add_flags(test_val, test_val));

    test_val = 0x0;
    int test_val_2 = 0x80000001;
    /* With subtracting:
        0xfff - 0x1000 - carry bit, no overflow - 0xffffffff
        0x0 - 0x1000 - carry bit, no overflow - 0xfffff000
        0xffffffff - 0x1000 - no carry bit, no overflow 
        0x80001000 - 0x1000 - no carry bit, no overflow
        0x80000fff - 0x1000 - no carry bit, overflow - 0x7fffffff
        0x80000000 - 0x1000 - no carry bit, overflow - 0x7ffff000
        0x80000000 - 0x7fffffff - no carry bit, overflow
        0x80000000 - 0x80000000 - no carry bit, no overflow (zero)
        0x80000000 - 0x80000001 - carry bit, no overflow
        0x1000 - 0x80000000 - carry bit, overflow - 0x80001000

        pos minus neg - should be pos
        neg minus pos - should be neg
        pos minus pos - always gonna be pos or 0, no overflow
        neg minus neg - always gonna be neg or 0, no overflow
     */
    // For sub, carry bit indicates unsigned overflow.  It happens when a bigger number is subtracted from a smaller number.  Ghidra uses INT_LESS to calculate CF in a sub.
    // For sub, overflow bit indicates signed overflow.  It can only happen when the operand signs are different.  If the result, in that case, doesn't have the same sign as the first operand, then it's an overflow.  Ghidra uses INT_SBORROW to calculat OF in a sub.
    printf("Investigate sub flags 0x%x 0x%x 0x%lx\n", test_val, test_val_2, investigate_sub_flags(test_val, test_val_2));

    printf("Big sub 1 %i\n", big_sub(1));
    printf("Big sub 0 %i\n", big_sub(0));
    printf("Big sub -1 %i\n", big_sub(-1));
    printf("Big sub -2 %i\n", big_sub(-2));
    printf("Big sub 0x80000001 %i\n", big_sub(0x80000001));
    printf("Big sub 0x80000000 %i\n", big_sub(0x80000000));
    printf("Big sub 0x7fffffff %i\n", big_sub(0x7fffffff));

    printf("Flags: C1Px AxZS TIDO\n");
    // carry, parity, adjust, zero, sign, trap, interupt enable, direction overflow

    printf("Div result 10/2 %li\n", div(10, 2));
    printf("Unsigned div result 10 / 2 %li\n", unsign_div(10, 2));
    printf("Div result -10/2 %li\n", div(-10, 2));
    printf("Unsigned div result -10 / 2 %li\n", unsign_div(-10, 2));

    return 0;
}
