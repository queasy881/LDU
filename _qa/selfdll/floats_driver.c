#include <stdio.h>
float fadd(float,float); float fsub(float,float); float fmul(float,float);
float fdiv(float,float); float favg(float,float); float fmax3(float,float,float);
float frelu(float); float fclamp(float,float,float); float flerp(float,float,float);
float fabsf_(float);
double dadd(double,double); double dmul(double,double); double dmax(double,double); double dpoly(double);
int f2i(float); float i2f(int); double i2d(int); float scale_int(int,float);
int fgt(float,float); int fsign(float); int fclass(float);
float dot2(const float*,const float*); float dot3(const float*,const float*);
float len2sq(const float*); void vscale2(float*,float);
float fsum(const float*,int); float fmaxarr(const float*,int);

int main(void){
    setvbuf(stdout,0,_IONBF,0);
    for(int i=-3;i<=3;i++){ float a=i*1.5f, b=(2-i)*0.75f;
        printf("fadd %.4f fsub %.4f fmul %.4f fdiv %.4f favg %.4f\n", fadd(a,b),fsub(a,b),fmul(a,b),fdiv(a,b),favg(a,b));
        printf("fmax3 %.4f relu %.4f clamp %.4f lerp %.4f fabs %.4f\n", fmax3(a,b,1.0f),frelu(a),fclamp(a,-1.0f,1.0f),flerp(a,b,0.25f),fabsf_(a)); }
    for(int i=-2;i<=3;i++){ double d=i*1.25;
        printf("dadd %.4f dmul %.4f dmax %.4f dpoly %.4f\n", dadd(d,2.0),dmul(d,3.0),dmax(d,0.5),dpoly(d)); }
    for(int i=-4;i<=4;i++){ float f=i*0.6f;
        printf("f2i %d i2f %.4f i2d %.4f scale %.4f gt %d sign %d class %d\n",
            f2i(f),i2f(i),i2d(i),scale_int(i,0.5f),fgt(f,0.0f),fsign(f),fclass(f)); }
    { float a[3]={1.5f,-2.0f,3.25f}, b[3]={0.5f,4.0f,-1.0f};
      printf("dot2 %.4f dot3 %.4f len2sq %.4f\n", dot2(a,b),dot3(a,b),len2sq(a));
      vscale2(a,2.0f); printf("vscale2 %.4f %.4f\n", a[0],a[1]); }
    { float arr[6]={3.0f,-1.5f,7.25f,0.0f,2.5f,-4.0f};
      printf("fsum %.4f fmaxarr %.4f\n", fsum(arr,6),fmaxarr(arr,6)); }
    return 0;
}
