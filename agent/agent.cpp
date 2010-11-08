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

int fd;
pid_t pid = 0;
vector <char*> file_name;
int file_num;
bool sockets, datagrams;

void readFromSocket(int fd, void* b, size_t count)
{
  char* buf = (char*) b;
  size_t received = 0;
  while (received < count)
  {
    size_t r = read(fd, buf + received, count - received);
    if (r == 0)
    {
      throw "connection is down";
    }
    if (r == -1)
    {
      throw "error reading from socket";
    }
    received += r;
  }
}

void recvInput(bool initial)
{
  int net_fd, length, namelength;
  if (sockets || datagrams)
  {
    net_fd = open("replace_data", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    write(net_fd, &file_num, sizeof(int));
  }
  for (int j = 0; j < file_num; j ++)
  {
    if (initial && !sockets && !datagrams)
    {
      readFromSocket(fd, &namelength, sizeof(int));
      if (namelength == -1)
      {
        write(fd, &namelength, sizeof(int));
        throw "main Avalanche agent is finished";
      }
      char* filename = new char[namelength + 1];
      readFromSocket(fd, filename, namelength);
      filename[namelength] = '\0';
      file_name.push_back(filename);
    }
    readFromSocket(fd, &length, sizeof(int));
    if (length == -1)
    {
      write(fd, &length, sizeof(int));
      throw "main Avalanche agent is finished";
    }
    char* file = new char[length];
    readFromSocket(fd, file, length);
    if (sockets || datagrams)
    {
      write(net_fd, &length, sizeof(int));
      write(net_fd, file, length);
    }
    else
    {
      int descr = open(file_name.at(j), O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
      if (descr == -1)
      {
        perror("open failed");
        close(fd);
        //exit(EXIT_FAILURE);
      }
      write(descr, file, length);
      close(descr);
    }
    delete[] file;
  }
  if (sockets || datagrams)
  {
    close(net_fd);
  }
}

void sig_hndlr(int signo)
{
  int startdepth = 0;
  int descr = open("startdepth.log", O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
  write(fd, "g", 1);
  try
  {
    recvInput(false);
    readFromSocket(fd, &startdepth, sizeof(int));
  }
  catch (const char* msg)
  {
    shutdown(fd, O_RDWR);
    close(fd);
    printf("coudln't receive non zero scored input: %s\n", msg);
  }
  write(descr, &startdepth, sizeof(int));
  close(descr);
  
  kill(pid, SIGUSR2);
}

void int_handler(int signo)
{
  shutdown(fd, SHUT_RDWR);
  close(fd);
  if (pid != 0)
  {
    kill(pid, SIGINT);
  }
  for (int i = 0; i < file_name.size(); i ++)
  {
    delete [](file_name.at(i));
  }
  file_name.clear();
}  
 
int main(int argc, char** argv)
{
  struct sockaddr_in stSockAddr;
  int res;
  bool requestNonZero = false;
  if ((argc > 3) && !strcmp(argv[3], "--request-non-zero"))
  {
    requestNonZero = true;
  }
 
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

  fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

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

  try
  {
    signal(SIGINT, int_handler);
    write(fd, "a", 1);

    int namelength, length, startdepth, invertdepth, alarm, tracegrindAlarm;
    int threads, argsnum, masklength, filtersNum, flength, received, net_fd;
    bool useMemcheck, leaks, traceChildren, checkDanger, debug, verbose, suppressSubcalls, STPThreadsAuto;
  
    readFromSocket(fd, &file_num, sizeof(int));
    if (file_num == -1)
    {
      write(fd, &file_num, sizeof(int));
      throw "main Avalanche agent is finished";
    }
    readFromSocket(fd, &sockets, sizeof(bool));
    readFromSocket(fd, &datagrams, sizeof(bool));
    recvInput(true);

    readFromSocket(fd, &startdepth, sizeof(int));
    readFromSocket(fd, &invertdepth, sizeof(int));
    readFromSocket(fd, &alarm, sizeof(int));
    readFromSocket(fd, &tracegrindAlarm, sizeof(int));
    readFromSocket(fd, &threads, sizeof(int));
    readFromSocket(fd, &argsnum, sizeof(int));
    readFromSocket(fd, &useMemcheck, sizeof(bool));
    readFromSocket(fd, &leaks, sizeof(bool));
    readFromSocket(fd, &traceChildren, sizeof(bool));
    readFromSocket(fd, &checkDanger, sizeof(bool));
    readFromSocket(fd, &debug, sizeof(bool));
    readFromSocket(fd, &verbose, sizeof(bool));
    readFromSocket(fd, &suppressSubcalls, sizeof(bool));
    readFromSocket(fd, &STPThreadsAuto, sizeof(bool));
 
    char* avalanche_argv[100];
    string argstr(argv[0]);
    size_t sl = argstr.find_last_of('/');
    if (sl != string::npos) 
    {
      avalanche_argv[0] = strdup((char*) (argstr.substr(0, sl + 1) + string("avalanche")).c_str());
    }
    else 
    {
      avalanche_argv[0] = "avalanche";
    }
    argstr.clear();
    int argv_delta = 0;

    if (!sockets && !datagrams)
    {
      for (int i = 0; i < file_num; i ++)
      {
        char s[512];
        sprintf(s, "--filename=%s", file_name.at(i));
        avalanche_argv[1 + i] = strdup(s);
      }
      argv_delta = file_num;
    }
  
    char depth[128];
    sprintf(depth, "--depth=%d", invertdepth);
    avalanche_argv[1 + argv_delta] = depth;

    char sdepth[128];
    sprintf(sdepth, "--startdepth=%d", startdepth);
    avalanche_argv[2 + argv_delta] = sdepth;

    char alrm[128];
    sprintf(alrm, "--alarm=%d", alarm);
    avalanche_argv[3 + argv_delta] = alrm;

    avalanche_argv[4 + argv_delta] = "--prefix=branch0_";

    if (STPThreadsAuto)
    {
      avalanche_argv[5 + argv_delta] = "--stp-threads-auto";
    }
    else
    {
      char thrds[128];
      sprintf(thrds, "--stp-threads=%d", threads);
      avalanche_argv[5 + argv_delta] = strdup(thrds);
    }

    int av_argc = 6 + argv_delta;
    if (requestNonZero)
    {
      avalanche_argv[6 + argv_delta] = "--agent";
      av_argc++;
    }

    int runs = 0;
    if (tracegrindAlarm != 0)
    {
      char alrm[128];
      sprintf(alrm, "--tracegrind-alarm=%d", tracegrindAlarm);
      avalanche_argv[av_argc++] = alrm;
    }
    if (useMemcheck)
    {
      avalanche_argv[av_argc++] = "--use-memcheck";
    }
    if (leaks)
    {
      avalanche_argv[av_argc++] = "--leaks";
    }
    if (traceChildren)
    {
      avalanche_argv[av_argc++] = "--trace-children";
    }
    if (checkDanger)
    {
      avalanche_argv[av_argc++] = "--check-danger";
    }
    if (debug)
    {
      avalanche_argv[av_argc++] = "--debug";
    }
    if (verbose)
    {
      avalanche_argv[av_argc++] = "--verbose";
    }
    if (sockets)
    {
      avalanche_argv[av_argc++] = "--sockets";
    }
    if (datagrams)
    {
      avalanche_argv[av_argc++] = "--datagrams";
    }
    if (suppressSubcalls)
    {
      avalanche_argv[av_argc++] = "--suppress-subcalls";
    }

    if (sockets)
    {
      int length, port;
      char buf[128], host[128], prt[128];
      readFromSocket(fd, &length, sizeof(int));
      readFromSocket(fd, buf, length);
      buf[length] = '\0';
      sprintf(host, "--host=%s", buf);
      avalanche_argv[av_argc++] = strdup(host);
      readFromSocket(fd, &port, sizeof(int));
      sprintf(prt, "--port=%d", port);
      avalanche_argv[av_argc++] = strdup(prt);
    }

    readFromSocket(fd, &masklength, sizeof(int));
    if (masklength != 0)
    {
      char* mask = new char[masklength];
      readFromSocket(fd, mask, masklength);
      int descr = open("mask", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
      if (descr == -1)
      {
        perror("open failed");
        close(fd);
        exit(EXIT_FAILURE);
      }
      write(descr, mask, masklength);
      close(descr);
      delete[] mask;
      avalanche_argv[av_argc++] = "--mask=mask";
    }

    readFromSocket(fd, &filtersNum, sizeof(int));
    for (int i = 0; i < filtersNum; i++)
    {
      int length;
      char buf[128], fltr[128];
      readFromSocket(fd, &length, sizeof(int));
      readFromSocket(fd, buf, length);
      buf[length] = '\0';
      sprintf(fltr, "--func-name=%s", buf);
      avalanche_argv[av_argc++] = fltr;
    } 

    readFromSocket(fd, &flength, sizeof(int));
    if (flength != 0)
    {
      char* filter = new char[flength];
      readFromSocket(fd, filter, flength);
      int descr = open("filter", O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
      if (descr == -1)
      {
        perror("open failed");
        close(fd);
        exit(EXIT_FAILURE);
      }
      write(descr, filter, flength);
      close(descr);
      delete[] filter;
      avalanche_argv[av_argc++] = "--func-file=filter";
    }

    for (int i = 0; i < argsnum; i++)
    {
      int arglength;
      readFromSocket(fd, &arglength, sizeof(int));
      char* arg = new char[arglength + 1];
      readFromSocket(fd, arg, arglength);
      arg[arglength] = '\0';
      avalanche_argv[av_argc++] = arg;
    }
    avalanche_argv[av_argc] = NULL;

    for (;;)
    {
      signal(SIGUSR1, sig_hndlr);
      pid = fork();
      if (pid == 0)
      {
        printf("starting child avalanche...\n");
        execvp(avalanche_argv[0], avalanche_argv);
      }
      wait(NULL);

      write(fd, "g", 1);
      recvInput(false);
    
      int startdepth;
      readFromSocket(fd, &startdepth, sizeof(int));

      char sdepth[128];
      sprintf(sdepth, "--startdepth=%d", startdepth);
      avalanche_argv[2 + argv_delta] = sdepth;

      char prefix[128];
      sprintf(prefix, "--prefix=branch%d_", ++runs);
      avalanche_argv[4 + argv_delta] = prefix; 
    }
  }
  catch (const char* msg)
  {
    shutdown(fd, SHUT_RDWR);
    close(fd);
    printf("exiting...\n");
  }

  for (int i = 0; i < file_name.size(); i ++)
  {
    delete [](file_name.at(i));
  }
  file_name.clear();
  return 0;
}

