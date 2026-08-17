#include <stdio.h>

static volatile signed char    g_sb;
static volatile short          g_sh;
static volatile int            g_sw;
static volatile long           g_sd;
static volatile unsigned char  g_ub;
static volatile unsigned short g_uh;
static volatile unsigned int   g_uw;
static volatile float          g_f;
static volatile double         g_d;

int main(void) {
    g_sb = -12;
    g_sh = -1234;
    g_sw = -123456;
    g_sd = -123456789012345L;
    g_ub = 0xAB;
    g_uh = 0xBEEF;
    g_uw = 0xDEADBEEF;
    g_f  = 3.14159f;
    g_d  = 2.718281828;

    signed char    lb  = g_sb;            
    short          lh  = g_sh;            
    int            lw  = g_sw;            
    long           ld  = g_sd;            
    unsigned char  lbu = g_ub;            
    unsigned short lhu = g_uh;            
    unsigned long  lwu = g_uw;            /*widened to force zero-extend*/
    float          flw = g_f;             
    double         fld = g_d;            

    printf("lb  = %d (expect -12)\n", (int)lb);
    printf("lh  = %d (expect -1234)\n", (int)lh);
    printf("lw  = %d (expect -123456)\n", lw);
    printf("ld  = %ld (expect -123456789012345)\n", ld);
    printf("lbu = %u (expect 171)\n", (unsigned)lbu);
    printf("lhu = %u (expect 48879)\n", (unsigned)lhu);
    printf("lwu = %lu (expect 3735928559)\n", lwu);
    printf("flw = %f (expect 3.141590)\n", flw);
    printf("fld = %f (expect 2.718282)\n", fld);

    return 0;
}
