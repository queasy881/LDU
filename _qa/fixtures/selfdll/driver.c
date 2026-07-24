/* Behavioural differential driver. Linked twice: once against the SOURCE impl,
 * once against the DECOMPILED impl. Prints a deterministic line per test; the two
 * runs' stdout are diffed. Any difference = a decompiler semantic bug.
 * Functions are declared with the source ABI; the decompiled versions use
 * long long for pointers but match on x64 (8-byte regs), so linkage is fine. */
#include <stdio.h>
#include <stdint.h>

int  my_add(int,int);   int my_sub(int,int);   int my_mul(int,int);
int  my_max(int,int);   int my_abs(int);       int my_clamp(int,int,int);
int  sum_to(int);       int64_t sum_array(const int*,int);
int  my_strlen(const char*); int count_bit(unsigned);
void my_swap(int*,int*); int deref_off(const int*,int); void set_range(int*,int,int);
typedef struct { int x,y,z,w; } Vec4;
int  vec4_sum(const Vec4*); void vec4_scale(Vec4*,int);
float favg(float,float); double dmax(double,double); float frelu(float);
int  my_fib(int);       int my_gcd(int,int);   int classify(int);
void seq_two(int*);     int fwd_add(int,int);
typedef struct { int id; int vals[4]; } Rec;
int  rec_sum(const Rec*); void rec_bump(Rec*,int);
int  mat_trace(const int*,int); int dot(const int*,const int*,int);
const int *find_max(const int*,int); int reverse_bits(unsigned);
int  str_eq(const char*,const char*); long long poly(int);

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);   /* unbuffered: last line printed = where it crashed */
    for (int a=-3; a<=3; a++) for (int b=-3; b<=3; b++)
        printf("add %d sub %d mul %d max %d\n", my_add(a,b), my_sub(a,b), my_mul(a,b), my_max(a,b));
    for (int x=-5; x<=5; x++) printf("abs %d clamp %d\n", my_abs(x), my_clamp(x,-2,2));
    for (int n=0; n<=8; n++) printf("sum_to %d fib %d classify %d\n", sum_to(n), my_fib(n), classify(n));
    { int arr[6]={5,-2,7,0,3,9}; printf("sum_array %lld\n",(long long)sum_array(arr,6));
      printf("deref_off %d %d\n", deref_off(arr,0), deref_off(arr,3)); }
    printf("strlen %d %d\n", my_strlen("hello world"), my_strlen(""));
    for (unsigned u=0; u<20u; u++) printf("count_bit %d\n", count_bit(u*2654435761u));
    { int a=11,b=22; my_swap(&a,&b); printf("swap %d %d\n", a, b); }
    { int buf[4]={0,0,0,0}; set_range(buf,4,42); printf("set_range %d %d %d %d\n",buf[0],buf[1],buf[2],buf[3]); }
    { int buf[4]={1,1,1,1}; seq_two(buf); printf("seq_two %d %d %d %d\n",buf[0],buf[1],buf[2],buf[3]); }
    { Vec4 v={1,2,3,4}; printf("vec4_sum %d\n", vec4_sum(&v)); vec4_scale(&v,3);
      printf("vec4_scale %d %d %d %d\n", v.x,v.y,v.z,v.w); }
    for (int a=1; a<=48; a+=7) for (int b=1; b<=13; b+=3) printf("gcd %d\n", my_gcd(a,b));
    for (int i=-3;i<=3;i++){ float fa=i*1.5f, fb=(3-i)*0.5f;
        printf("favg %.4f frelu %.4f dmax %.4f\n", favg(fa,fb), frelu(fa), dmax((double)fa,(double)fb)); }
    printf("fwd_add %d\n", fwd_add(9, 33));
    { Rec r={10,{1,2,3,4}}; printf("rec_sum %d\n", rec_sum(&r)); rec_bump(&r,5);
      printf("rec_bump %d %d %d %d %d\n", r.id, r.vals[0], r.vals[1], r.vals[2], r.vals[3]); }
    { int m[9]={1,2,3,4,5,6,7,8,9}; printf("mat_trace %d\n", mat_trace(m,3)); }
    { int a[4]={1,2,3,4}, b[4]={5,6,7,8}; printf("dot %d\n", dot(a,b,4)); }
    { int a[5]={3,7,2,9,4}; printf("find_max %d\n", *find_max(a,5)); }
    for (unsigned u=0; u<8u; u++) printf("reverse_bits %d\n", reverse_bits(u*0x11111111u));
    printf("str_eq %d %d %d\n", str_eq("abc","abc"), str_eq("abc","abd"), str_eq("",""));
    for (int x=-2; x<=3; x++) printf("poly %lld\n", (long long)poly(x));
    return 0;
}
