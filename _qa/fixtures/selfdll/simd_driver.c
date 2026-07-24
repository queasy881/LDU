#include <stdio.h>
#include <stdint.h>
void iscale(int*,int,int); void iadd(int*,const int*,int); void isub(int*,const int*,int);
void iaxpy(int*,const int*,int,int);
int isum(const int*,int); int64_t isum64(const int*,int); int idot(const int*,const int*,int); int imax(const int*,int);
void fscale(float*,int,float); void fadd_v(float*,const float*,int); void fsaxpy(float*,const float*,float,int);
float fsumv(const float*,int); float fdotv(const float*,const float*,int);

int main(void){
    setvbuf(stdout,0,_IONBF,0);
    int A[10]={5,-2,7,0,3,9,-4,6,1,8}, B[10]={1,2,3,4,5,6,7,8,9,10};
    { int a[10]; for(int i=0;i<10;i++)a[i]=A[i]; iscale(a,10,3);
      printf("iscale"); for(int i=0;i<10;i++)printf(" %d",a[i]); printf("\n"); }
    { int a[10]; for(int i=0;i<10;i++)a[i]=A[i]; iadd(a,B,10);
      printf("iadd"); for(int i=0;i<10;i++)printf(" %d",a[i]); printf("\n"); }
    { int a[10]; for(int i=0;i<10;i++)a[i]=A[i]; isub(a,B,10);
      printf("isub"); for(int i=0;i<10;i++)printf(" %d",a[i]); printf("\n"); }
    { int y[10]; for(int i=0;i<10;i++)y[i]=A[i]; iaxpy(y,B,4,10);
      printf("iaxpy"); for(int i=0;i<10;i++)printf(" %d",y[i]); printf("\n"); }
    for(int n=1;n<=10;n++)
      printf("isum %d isum64 %lld idot %d imax %d\n", isum(A,n),(long long)isum64(A,n),idot(A,B,n),imax(A,n));
    float FA[10]={1.5f,-2.0f,3.25f,0.5f,4.0f,-1.0f,2.5f,-3.5f,0.75f,6.0f};
    float FB[10]={0.5f,1.0f,-1.5f,2.0f,-0.5f,3.0f,1.25f,-2.0f,0.25f,-1.0f};
    { float a[10]; for(int i=0;i<10;i++)a[i]=FA[i]; fscale(a,10,2.0f);
      printf("fscale"); for(int i=0;i<10;i++)printf(" %.4f",a[i]); printf("\n"); }
    { float a[10]; for(int i=0;i<10;i++)a[i]=FA[i]; fadd_v(a,FB,10);
      printf("fadd_v"); for(int i=0;i<10;i++)printf(" %.4f",a[i]); printf("\n"); }
    { float y[10]; for(int i=0;i<10;i++)y[i]=FA[i]; fsaxpy(y,FB,1.5f,10);
      printf("fsaxpy"); for(int i=0;i<10;i++)printf(" %.4f",y[i]); printf("\n"); }
    for(int n=1;n<=10;n++)
      printf("fsumv %.4f fdotv %.4f\n", fsumv(FA,n),fdotv(FA,FB,n));
    return 0;
}
