#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int* i;
int j = 0;

static int g(int val)
{
  val ++;
}

static int f(unsigned long long int val)
{
  if(val > 3)
    j ++;
  g(val);
  return 1;
}

int main(int argc, char** argv)
{
  int k = 0;
  int  fd1 = open(argv[1], O_RDONLY | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
  char local[4];
  read(fd1, local, 3);
  //printf("%d", (int)local[0]);
  if(local[0] < 5)
    j ++;
  f(local[1] + 0x0011111111111111ULL);
  //if(local[1] < 3)
  //  j ++;
  //if(local[2] < 1)
  //  j ++;
  //f(local[2]);
  //for(k = 1; k < 3; k ++)
  //  f(local[k]);
  if(j == 2)
    i = (int*) malloc(sizeof(int));
  *i = 33;
  //printf("%d %d %d\n", local[0], local[1], j);

  return 0;
}

