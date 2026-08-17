#include <stdio.h>

static inline unsigned long rdcycle(void) {
    unsigned long c;
    __asm__ volatile ("rdcycle %0" : "=r"(c));
    return c;
}

static volatile long array[21];

int main(void) {
    long idx = 0;

    __asm__ volatile ("fence" ::: "memory");

    unsigned long t0 = rdcycle();

    // Each step: store to array[idx], then load back → STQ forwarding
    // The loaded value (= what was just stored) is the next index

    array[idx] = 1;  idx = array[idx];  /* idx = 1 */
    array[idx] = 2;  idx = array[idx];  /* idx = 2 */
    array[idx] = 3;  idx = array[idx];  /* idx = 3 */
    array[idx] = 4;  idx = array[idx];  /* idx = 4 */
    array[idx] = 5;  idx = array[idx];  /* idx = 5 */
    array[idx] = 6;  idx = array[idx];  /* idx = 6 */
    array[idx] = 7;  idx = array[idx];  /* idx = 7 */
    array[idx] = 8;  idx = array[idx];  /* idx = 8 */
    array[idx] = 9;  idx = array[idx];  /* idx = 9 */
    array[idx] = 10; idx = array[idx];  /* idx = 10 */

    unsigned long t1 = rdcycle();

    printf("cycles: %lu\n", t1 - t0);
    printf("final idx: %ld\n", idx);
    return 0;
}
