#ifndef RDTSC_H_
#define RDTSC_H_

static inline unsigned long long rdtsc() {
    unsigned long long ret;

    __asm__ __volatile__ ("cpuid" : : : "rax", "rbx", "rcx", "rdx");
    __asm__ __volatile__ ( \
        "rdtsc\n\t" \
        "shlq       $32, %%rdx\n\t" \
        "orq        %%rdx, %%rax\n\t" \
        "movq       %%rax, %0" : "=g" (ret) : : "rax", "rdx");
    
    return ret;
}

#endif /* RDTSC_H_ */

