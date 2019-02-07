#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
  sleep(2);
  fprintf(stderr,"ENV S2=%s\n",getenv("S2"));
  printf("Exiting with %d\n",argc+1);
  return argc+1;
}
