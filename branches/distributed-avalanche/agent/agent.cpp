/* Server code in C */
 
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <vector>
#include <string>

using namespace std;
 
int main(int argc, char** argv)
{
  struct sockaddr_in stSockAddr;
  int res;
 
  memset(&stSockAddr, 0, sizeof(struct sockaddr_in));
 
  stSockAddr.sin_family = AF_INET;
  stSockAddr.sin_port = htons(atoi(argv[2]));
  res = inet_pton(AF_INET, argv[1], &stSockAddr.sin_addr);
 
  if (res < 0)
  {
    perror("error: first parameter is not a valid address family");
    exit(EXIT_FAILURE);
  }
  else if (res == 0)
  {
    perror("char string (second parameter does not contain valid ipaddress");
    exit(EXIT_FAILURE);
  }

  int fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (fd == -1)
  {
    perror("cannot create socket");
    exit(EXIT_FAILURE);
  }
    
  res = connect(fd, (const struct sockaddr*)&stSockAddr, sizeof(struct sockaddr_in));
 
  if (res < 0)
  {
    perror("error connect failed");
    close(fd);
    exit(EXIT_FAILURE);
  }  

  printf("connected\n");

  write(fd, "a", 1);
  int namelength, length, startdepth, invertdepth, alarm, argsnum;
  bool useMemcheck, leaks, traceChildren, checkDanger;
  res = read(fd, &namelength, sizeof(int));
  if (res == 0)
  {
    exit(0);
  }
  //printf("namelength=%d\n", namelength);
  char* filename = new char[namelength + 1];
  int received = 0;
  while (received < namelength)
  {
    received += read(fd, filename + received, namelength - received);
  }
  filename[namelength] = '\0';
  //printf("filename=%s\n", filename);
  read(fd, &length, sizeof(int));
  //printf("length=%d\n", length);
  char* file = new char[length];
  received = 0;
  while (received < length)
  {
    received += read(fd, file + received, length - received);
  }
  printf("\n");
  int descr = open(filename, O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
  write(descr, file, length);
  close(descr);
  delete[] file;
  read(fd, &startdepth, sizeof(int));
  //printf("startdepth=%d\n", startdepth);
  read(fd, &invertdepth, sizeof(int));
  //printf("invertdepth=%d\n", invertdepth);
  read(fd, &alarm, sizeof(int));
  //printf("alarm=%d\n", alarm);
  read(fd, &argsnum, sizeof(int));
  //printf("argsnum=%d\n", argsnum);

  read(fd, &useMemcheck, sizeof(bool));
  //printf("useMemcheck=%d\n", useMemcheck);
  read(fd, &leaks, sizeof(bool));
  //printf("leaks=%d\n", leaks);
  read(fd, &traceChildren, sizeof(bool));
  //printf("traceChildren=%d\n", traceChildren);
  read(fd, &checkDanger, sizeof(bool));
  //printf("checkDanger=%d\n", checkDanger);

  char* avalanche_argv[100];
  string argstr(argv[0]);
  size_t sl = argstr.find_last_of('/');
  if (sl != string::npos) {
      avalanche_argv[0] = (char*) (argstr.substr(0, sl + 1) + string("avalanche")).c_str();
  }
  else {
      avalanche_argv[0] = "avalanche";
  }
  printf("argv[0]=%s\n", avalanche_argv[0]);
  char s[128];
  sprintf(s, "--filename=%s", filename);
  avalanche_argv[1] = s;
  printf("argv[1]=%s\n", avalanche_argv[1]);

  char depth[128];
  sprintf(depth, "--depth=%d", invertdepth);
  avalanche_argv[2] = depth;
  printf("argv[2]=%s\n", avalanche_argv[2]);

  char sdepth[128];
  sprintf(sdepth, "--startdepth=%d", startdepth);
  avalanche_argv[3] = sdepth;
  printf("argv[3]=%s\n", avalanche_argv[3]);

  char alrm[128];
  sprintf(alrm, "--alarm=%d", alarm);
  avalanche_argv[4] = alrm;
  printf("argv[4]=%s\n", avalanche_argv[4]);

  avalanche_argv[5] = "--prefix=branch0_";
  printf("argv[5]=%s\n", avalanche_argv[5]);
  int runs = 0;

  int av_argc = 6;
  if (useMemcheck)
  {
    avalanche_argv[av_argc++] = "--use-memcheck";
    printf("argv[%d]=%s\n", av_argc - 1, avalanche_argv[av_argc - 1]);
  }
  if (leaks)
  {
    avalanche_argv[av_argc++] = "--leaks";
    printf("argv[%d]=%s\n", av_argc - 1, avalanche_argv[av_argc - 1]);
  }
  if (traceChildren)
  {
    avalanche_argv[av_argc++] = "--trace-children";
    printf("argv[%d]=%s\n", av_argc - 1, avalanche_argv[av_argc - 1]);
  }
  if (checkDanger)
  {
    avalanche_argv[av_argc++] = "--check-danger";
    printf("argv[%d]=%s\n", av_argc - 1, avalanche_argv[av_argc - 1]);
  }

  for (int i = 0; i < argsnum; i++)
  {
    int arglength;
    read(fd, &arglength, sizeof(int));
    char* arg = new char[arglength + 1];
    read(fd, arg, arglength);
    arg[arglength] = '\0';
    avalanche_argv[av_argc++] = arg;
    printf("argv[%d]=%s\n", av_argc - 1, avalanche_argv[av_argc - 1]);
  }
  avalanche_argv[av_argc] = NULL;
  printf("argv[%d]=NULL\n", av_argc);

  for (;;)
  {
    if (fork() == 0)
    {
      printf("starting child avalanche...\n");
      execvp(avalanche_argv[0], avalanche_argv);
    }
    wait(NULL);

    write(fd, "g", 1);
    int length, startdepth;
    int res = read(fd, &length, sizeof(int));
    if (res == 0)
    {
      exit(0);
    }
    char* file = new char[length];
    received = 0;
    while (received < length)
    {
      received += read(fd, file + received, length - received);
    }
    read(fd, &startdepth, sizeof(int));

    int descr = open(filename, O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
    write(descr, file, length);
    close(descr);
    delete[] file;

    char sdepth[128];
    sprintf(sdepth, "--startdepth=%d", startdepth);
    avalanche_argv[3] = sdepth;
    printf("argv[3]=%s\n", avalanche_argv[3]);

    char prefix[128];
    sprintf(prefix, "--prefix=branch%d_", ++runs);
    avalanche_argv[5] = prefix;
    printf("argv[5]=%s\n", avalanche_argv[5]);    
  }

  return 0;
}

