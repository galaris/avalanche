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
  stSockAddr.sin_port = htons(atoi(argv[1]));
  res = inet_pton(AF_INET, "127.0.0.1", &stSockAddr.sin_addr);
 
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

  write(fd, "g", 1);
  int length, startdepth, invertdepth, alarm;
  bool useMemcheck, leaks, traceChildren, checkDanger;
  read(fd, &length, sizeof(int));
  char* file = new char[length];
  int received = 0;
  while (received < length)
  {
    received += read(fd, file + received, length - received);
  }
  read(fd, &startdepth, sizeof(int));
  read(fd, &invertdepth, sizeof(int));
  read(fd, &alarm, sizeof(int));
  read(fd, &useMemcheck, sizeof(bool));
  read(fd, &leaks, sizeof(bool));
  read(fd, &traceChildren, sizeof(bool));
  read(fd, &checkDanger, sizeof(bool));

  for (;;)
  {
    char* avalanche_argv[10];
    string argstr(argv[0]);
    size_t sl = argstr.find_last_of('/');
    if (sl != string::npos) {
        avalanche_argv[0] = (char*) (argstr.substr(0, sl + 1) + string("agent")).c_str();
    }
    else {
        avalanche_argv[0] = "agent";
    }
    avalanche_argv[1] = "--filename=avalanche_input";

    int descr = open("avalanche_input", O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
    write(descr, file, length);
    close(descr);
    delete[] file;

    char depth[128];
    sprintf(depth, "--depth=%d", invertdepth);
    avalanche_argv[2] = depth;

    char sdepth[128];
    sprintf(sdepth, "--startdepth=%d", startdepth);
    avalanche_argv[3] = sdepth;

    char alrm[128];
    sprintf(depth, "--alarm=%d", alarm);
    avalanche_argv[4] = alrm;

    int argc = 5;
    if (useMemcheck)
    {
      avalanche_argv[argc++] = "--use-memcheck";
    }
    if (leaks)
    {
      avalanche_argv[argc++] = "--leaks";
    }
    if (traceChildren)
    {
      avalanche_argv[argc++] = "--trace-children";
    }
    if (checkDanger)
    {
      avalanche_argv[argc++] = "--check-danger";
    }
    avalanche_argv[argc] = NULL;
    if (fork() == 0)
    {
      execvp(avalanche_argv[0], avalanche_argv);
    }
    wait(NULL);
    write(fd, "g", 1);
    read(fd, &length, sizeof(int));
    file = new char[length];
    received = 0;
    while (received < length)
    {
      received += read(fd, file + received, length - received);
    }
    read(fd, &startdepth, sizeof(int));
  }

  return 0;
}

