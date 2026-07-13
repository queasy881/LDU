#include <stdio.h>
#include <stdint.h>
void t_void(int*); signed char t_char(int); unsigned char t_uchar(int);
short t_short(int); unsigned short t_ushort(int); int t_int(int); unsigned int t_uint(int);
long long t_ll(int); unsigned long long t_ull(int); float t_float(int); double t_double(int);
int *t_intptr(int*,int); char *t_charptr(char*,int); const void *t_voidptr(const int*);
long long t_deref_ll(const long long*);
long long mix_widen(char,short,int); int mix_narrow(long long); unsigned mix_shift(unsigned,int);
int sext_byte(const char*); unsigned zext_byte(const unsigned char*);
typedef struct { char c; int i; long long ll; float f; double d; } Mixed;
long long mixed_read(const Mixed*); void mixed_write(Mixed*,int);
int t_bool(int,int); int t_select(int);

int main(void){
    setvbuf(stdout,0,_IONBF,0);
    for(int x=-5;x<=5;x++){
        int p=x;
        printf("char %d uchar %u short %d ushort %u int %d uint %u\n",
            t_char(x),(unsigned)t_uchar(x),t_short(x),(unsigned)t_ushort(x),t_int(x),t_uint(x));
        printf("ll %lld ull %llu float %.4f double %.4f\n",
            (long long)t_ll(x),(unsigned long long)t_ull(x),t_float(x),t_double(x));
        t_void(&p); printf("void %d bool %d select %d\n", p, t_bool(x,0), t_select(x*30));
    }
    { int a[5]={10,20,30,40,50}; printf("intptr %d\n", *t_intptr(a,3)); }
    { char s[]="abcdef"; printf("charptr %c\n", *t_charptr(s,4)); }
    { int a[3]={7,8,9}; const void *v=t_voidptr(a); printf("voidptr %d\n", *(const int*)v); }
    { long long q=123456789012LL; printf("deref_ll %lld\n", t_deref_ll(&q)); }
    for(int i=-3;i<=3;i++)
        printf("widen %lld narrow %d shift %u\n", mix_widen((char)i,(short)(i*100),i*10000), mix_narrow(0x1122334455LL+i), mix_shift(0xF0F0F0F0u,i+4));
    { char cb[2]={-5,120}; unsigned char ub[2]={200,55};
      printf("sext %d zext %u\n", sext_byte(cb), zext_byte(ub)); }
    { Mixed m; mixed_write(&m,6); printf("mixed_read %lld write %d %d %lld %.4f %.4f\n",
        (long long)mixed_read(&m), m.c, m.i, (long long)m.ll, m.f, m.d); }
    return 0;
}
