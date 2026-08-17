#include <stdio.h>

static inline unsigned long rdcycle(void) {
    unsigned long c;
    __asm__ volatile ("rdcycle %0" : "=r"(c));
    return c;
}

// chain[i] points to chain[i+1], chain[20] = NULL 
static void *chain[21];

int main(void) {
    for (int i = 0; i < 20; i++)
        chain[i] = &chain[i+1];
    chain[20] = (void *)0;

    /* fence: drain STQ so all loads hit cache */
    __asm__ volatile ("fence" ::: "memory");

    void **p = (void **)&chain[0];

    unsigned long t0 = rdcycle();

    //dependent pointer-chasing: each load uses previous result as address
    p = *p; p = *p; p = *p; p = *p; p = *p;
    p = *p; p = *p; p = *p; p = *p; p = *p;
    p = *p; p = *p; p = *p; p = *p; p = *p;
    p = *p; p = *p; p = *p; p = *p;

    unsigned long t1 = rdcycle();

    printf("cycles: %lu\n", t1 - t0);
    printf("final: %lu\n", (unsigned long)p);
    return 0;
}
