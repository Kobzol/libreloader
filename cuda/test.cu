#include <iostream>
#include <cstdio>

__global__ void kernel(int* p)
{
  p[threadIdx.x] = threadIdx.x;
  printf("ahoj\n");  
}

int main(int argc, char** argv)
{
  int* dPtr;
  cudaMalloc(&dPtr, sizeof(int) * 10);
  
  kernel<<<dim3(1,1,1), dim3(10,1,1)>>>(dPtr);
  
  int ptr[10];
  cudaMemcpy(&ptr[0], dPtr, sizeof(int) * 10, cudaMemcpyDeviceToHost);
  
  for (int i = 0; i < 10; i++)
  {
    std::cout << ptr[i] << std::endl;  
  }

  return 0;
}
