#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int* i;
int j = 0;

int g(char val)
{
  val ++;
  int y = 14;
  if(val < 3)
    j ++;
  return 1;
}

int f(char val)
{
  int x = 90;
  x += 11;
  //if(val < 4)
  //   j ++;
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
  //l(local[0]);
  //f(local[0]);
  f(local[1]);
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

