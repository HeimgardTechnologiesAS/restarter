#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  printf("this is stdout 1\n");
  fprintf(stderr,"this is stderr 1\n");
  sleep(20);
  printf("this is stdout 2\n");
  fprintf(stderr,"this is stderr 2\n");
  fprintf(stderr,"will now abort\n");
  abort();
  sleep(30);
  return 0;
}
