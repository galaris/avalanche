#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

char global[5];
int i;

int main(int argc, char** argv)
{
  int  j = 0;
  char local[3];
  int  fd1 = open(argv[1], O_RDONLY | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);

  read(fd1, local, 3);
  if (local[0] < 5) {
      j++;
  }
  if (local[1] < 3) {
      j++;
  }
  if (j == 2) {
      i = 100;
  }
  global[i - 100] = 0;
  return 0;
}

