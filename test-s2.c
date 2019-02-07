#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
  sleep(2);
  printf("Exiting with %d\n",argc+1);
  return argc+1;
}
