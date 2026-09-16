struct Node {
    struct Node *next;
    long value;
};

volatile struct Node *g_head;

extern void noop(void);
extern void touch(volatile long *p);
extern long *identity(long *p);

long dependent_chain_load(void) {
    struct Node *p = (struct Node *)g_head;   /* load 1: base is NOT a chain */
    return p->value;                           /* load 2: base (p) is load 1's dest */
}

long direct_stack_load(void) {
    volatile long buf[4] = {10, 20, 30, 40}; /* volatile forces real stack traffic */
    return buf[1];                            /* load: base is sp, offset is constant */
}

long arithmetic_propagates_safety(long n) {
    long p = (long)g_head;      /* load: safe, marks p safe */
    long q = p << n;              /* shift: reads p(safe) -> marks q safe (not a load or the stack) */
    return *(long *)(q + 8);       /* load: base=q, plain under dep/both via the arithmetic, not a load chain */
}

long x8_without_frame_pointer(void) {
    struct Node *p = (struct Node *)g_head;  /* load 1: p ends up allocated to x8/s0 */
    noop();                                    /* no VLA here -> x8 is NOT a frame pointer */
    return p->value;                           /* load 2: base=x8, must not be treated as a safe stack base */
}

long chain_survives_call(int n) {
    long vla[n];
    for (int i = 0; i < n; i++)
        vla[i] = i;
    struct Node *p = (struct Node *)g_head;   /* load: safe */
    noop();                                     /* real call */
    return p->value + vla[0];   /* load: base=s2, (normal ld )safe under dep/both - survives the call */
}

long stack_load_needs_both(void) {
    volatile long buf[300];   /* 300 * 8 = 2400 bytes, past the 2047-byte limit - 12 bit immediate */
    touch(buf);               /* forces buf to actually be allocated on the stack */
    return buf[290];          /* load: base = sp + arithmetic, not sp directly - safwe only under both*/
}

long x8_as_frame_pointer(int n) {
    volatile long fixed = 42;
    long vla[n];
    long total = 0;
    for (int i = 0; i < n; i++)
        vla[i] = i;
    for (int i = 0; i < n; i++)
        total += vla[i];
    return total + fixed;         /* load: base = fp (x8) directly - hasFp - safe stack load*/
}

long call_result_not_trusted(void) {
    long *p = (long *)g_head;   /* safe: direct load from g_head */
    long *q = identity(p);       /* q must NOT inherit p's safety just because
                                   * p was a safe argument to this call */
    return *q;                    /* must stay hardened */
}
