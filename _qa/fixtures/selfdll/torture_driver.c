#include <stdio.h>
int fwd6(int,int,int,int,int,int); long long fwd8(int,int,int,int,int,int,int,int);
int asr(int,int); unsigned lsr(unsigned,int); int asr_const(int);
int slen(const char*); int sum_until_zero(const int*);
long cas_add(volatile long*,long);
int stack_arr(int); int tail_phi(int,int);
long long sdiv(long long); long long smod(long long);
int sdiv32(int); int smod32(int); unsigned udiv3(unsigned); unsigned udiv7(unsigned);
unsigned umod7(unsigned); unsigned long long udiv10(unsigned long long);
long long sdivn7(long long); int sdiv100(int);
unsigned long long poison5(unsigned long long);
int rotloop(int,int);

int main(void){
    setvbuf(stdout,0,_IONBF,0);
    printf("fwd6 %d %d\n", fwd6(1,2,3,4,5,6), fwd6(-1,-2,-3,-4,-5,-6));
    printf("fwd8 %lld %lld\n", fwd8(1,2,3,4,5,6,7,8), fwd8(10,20,30,40,50,60,70,80));
    for(int x=-13;x<=13;x+=7) for(int n=0;n<=3;n++) printf("asr %d ", asr(x,n));
    printf("\n");
    for(unsigned x=0xF0000000u;x;x>>=8) printf("lsr %u ", lsr(x,4));
    printf("\n");
    printf("asrc %d %d %d\n", asr_const(-13), asr_const(-1), asr_const(255));
    { const char* s="hello, torture"; printf("slen %d\n", slen(s)); }
    { int a[]={3,1,4,1,5,9,2,6,0}; printf("suz %d\n", sum_until_zero(a)); }
    { long v=100; printf("cas %ld %ld\n", cas_add(&v,5), v); }
    for(int n=0;n<=16;n+=4) printf("sa %d ", stack_arr(n));
    printf("\n");
    for(int x=-3;x<=3;x++) printf("tp %d %d ", tail_phi(x,1), tail_phi(x,0));
    printf("\n");
    for(long long a=-20;a<=20;a+=7) printf("sd %lld %lld ", sdiv(a), smod(a));
    printf("\n");
    for(int x=-100;x<=100;x+=13) printf("s32 %d %d ", sdiv32(x), smod32(x));
    printf("\n");
    for(unsigned x=0;x<=100;x+=13) printf("u %u %u %u ", udiv3(x), udiv7(x), umod7(x));
    printf("\n");
    for(unsigned long long x=0;x<=1000;x+=137) printf("u64 %llu ", udiv10(x));
    printf("\n");
    for(long long x=-50;x<=50;x+=17) printf("n7 %lld ", sdivn7(x));
    for(int x=-1000;x<=1000;x+=333) printf("s100 %d ", sdiv100(x));
    printf("\n");
    for(unsigned long long x=0x100000000ULL;x<=0x500000000ULL;x+=0x123456789ULL) printf("p5 %llu ", poison5(x));
    printf("\n");
    for(int n=0;n<=9;n++) for(int seed=-3;seed<=3;seed++) printf("rl %d ", rotloop(n,seed));
    printf("\n");
    return 0;
}
