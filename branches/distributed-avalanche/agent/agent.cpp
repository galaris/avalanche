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

#define READ(var, type, fmt, sanity_check) \
    do \
    { \
      if (read(fd, &var, sizeof(type)) <= 0) conn_error("connection with server is down"); \
      if (sanity_check && var < 0) conn_error("bad data"); \
      printf(#var "=%" fmt "\n", var); \
    } \
    while(0) 

using namespace std;

int fd;
pid_t pid;
vector <char*> file_name;
int file_num;

void conn_error(const char* msg)
{
  printf("%s\n", msg);
  close(fd);
  for (int i = 0; i < file_name.size(); i ++)
  {
    delete [](file_name.at(i));
  }
  exit(EXIT_FAILURE);
}

void sig_hndlr(int signo)
{
  write(fd, "g", 1);
  int length, startdepth = 0;
  int descr = open("startdepth.log", O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
  for (int i = 0; i < file_num; i ++)
  {
    int res = read(fd, &length, sizeof(int));
    if (res < 1)
    {
      write(descr, &startdepth, sizeof(int));
      close(descr);   
      kill(pid, SIGUSR2); 
      return;
    }
    if (length <= 0)
    {
      write(descr, &startdepth, sizeof(int));
      close(descr);   
      kill(pid, SIGUSR2); 
      conn_error("bad data");
    }
    char* file = new char[length];
    int received = 0;
    while (received < length)
    {
      int r = read(fd, file + received, length - received);
      if (r < 1)
      {
        write(descr, &startdepth, sizeof(int));
        close(descr);
        kill(pid, SIGUSR2);
        return;
      }
      received += r;
    }
    int fdescr = open(file_name.at(i), O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
    write(fdescr, file, length);
    close(fdescr);
    delete[] file;
  }
  read(fd, &startdepth, sizeof(int));
  write(descr, &startdepth, sizeof(int));
  close(descr);
  
  kill(pid, SIGUSR2);
}
 
int main(int argc, char** argv)
{
  signal(SIGPIPE, SIG_IGN);
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

  if (write(fd, "a", 1) < 1) conn_error("connection with server is down");
  int namelength, length, startdepth, invertdepth, alarm, tracegrindAlarm, threads, argsnum;
  bool useMemcheck, leaks, traceChildren, checkDanger, debug, verbose, sockets, datagrams, suppressSubcalls;
  int received, net_fd;
  
  READ(file_num, int, "d", true);
  READ(sockets, bool, "d", false);
  READ(datagrams, bool, "d", false);
  if (sockets || datagrams)
  {
    net_fd = open("replace_data", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    write(net_fd, &file_num, sizeof(int));
  }
  for (int j = 0; j < file_num; j ++)
  {
    char *filename;
    if (!sockets && !datagrams)
    {
      READ(namelength, int, "d", true);
      filename = new char[namelength + 1];
      received = 0;
      while (received < namelength)
      {
        res = read(fd, filename + received, namelength - received);
        if (res < 1) conn_error("connection with server is down");
        received += res;
      }
      filename[namelength] = '\0';
      file_name.push_back(strdup(filename));
      printf("filename=%s\n", filename);
    }
    READ(length, int, "d", true);
    char* file = new char[length];
    received = 0;
    while (received < length)
    {
      res = read(fd, file + received, length - received);
      if (res < 0) conn_error("connection with server is down");
      received += res;
    }
    printf("\n");
    if (sockets || datagrams)
    {
      write(net_fd, &length, sizeof(int));
      write(net_fd, file, length);
      close(net_fd);
    }
    else
    {
      int descr = open(filename, O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
      if (descr == -1)
      {
        perror("open failed");
        close(fd);
        exit(EXIT_FAILURE);
      }
      write(descr, file, length);
      delete []filename;
      close(descr);
    }
    delete[] file;
  }
  READ(startdepth, int, "d", true);
  READ(invertdepth, int, "d", true);
  READ(alarm, int, "d", true);
  READ(tracegrindAlarm, int, "d", true);
  READ(threads, int, "d", true);
  READ(argsnum, int, "d", true);
  READ(useMemcheck, bool, "d", false);
  READ(leaks, bool, "d", false);
  READ(traceChildren, bool, "d", false);
  READ(checkDanger, bool, "d", false);
  READ(debug, bool, "d", false);
  READ(verbose, bool, "d", false);
  READ(suppressSubcalls, bool, "d", false);
 
  char* avalanche_argv[100];
  string argstr(argv[0]);
  size_t sl = argstr.find_last_of('/');
  if (sl != string::npos) {
      avalanche_argv[0] = strdup((char*) (argstr.substr(0, sl + 1) + string("avalanche")).c_str());
  }
  else {
      avalanche_argv[0] = "avalanche";
  }
  argstr.clear();
  for (int i = 0; i < file_num; i ++)
  {
    char s[128];
    sprintf(s, "--filename=%s", file_name.at(i));
    avalanche_argv[1 + i] = strdup(s);
  }

  char depth[128];
  sprintf(depth, "--depth=%d", invertdepth);
  avalanche_argv[1 + file_num] = depth;

  char sdepth[128];
  sprintf(sdepth, "--startdepth=%d", startdepth);
  avalanche_argv[2 + file_num] = sdepth;

  char alrm[128];
  sprintf(alrm, "--alarm=%d", alarm);
  avalanche_argv[3 + file_num] = alrm;

  avalanche_argv[4 + file_num] = "--prefix=branch0_";

  avalanche_argv[5 + file_num] = "--agent";

  char thrds[128];
  sprintf(thrds, "--stp-threads=%d", threads);
  avalanche_argv[6 + file_num] = thrds;
  for (int i = 0; i < 7 + file_num; i ++)
  {
    printf("argv[%d]=%s\n", i, avalanche_argv[i]);
  }
  int runs = 0;

  int av_argc = 7 + file_num;
  if (tracegrindAlarm != 0)
  {
    char alrm[128];
    sprintf(alrm, "--tracegrind-alarm=%d", tracegrindAlarm);
    avalanche_argv[av_argc++] = alrm;
    printf("argv[%d]=%s\n", av_argc - 1, avalanche_argv[av_argc - 1]);
  }
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
  if (debug)
  {
    avalanche_argv[av_argc++] = "--debug";
    printf("argv[%d]=%s\n", av_argc - 1, avalanche_argv[av_argc - 1]);
  }
  if (verbose)
  {
    avalanche_argv[av_argc++] = "--verbose";
    printf("argv[%d]=%s\n", av_argc - 1, avalanche_argv[av_argc - 1]);
  }
  if (sockets)
  {
    avalanche_argv[av_argc++] = "--sockets";
    printf("argv[%d]=%s\n", av_argc - 1, avalanche_argv[av_argc - 1]);
  }
  if (datagrams)
  {
    avalanche_argv[av_argc++] = "--datagrams";
    printf("argv[%d]=%s\n", av_argc - 1, avalanche_argv[av_argc - 1]);
  }
  if (suppressSubcalls)
  {
    avalanche_argv[av_argc++] = "--suppress-subcalls";
    printf("argv[%d]=%s\n", av_argc - 1, avalanche_argv[av_argc - 1]);
  }

  if (sockets)
  {
    int length;
    READ(length, int, "d", true);
    char buf[128];
    if (read(fd, buf, length) < 0) conn_error("connection with server is down");
    buf[length] = '\0';
    char host[128];
    sprintf(host, "--host=%s", buf);
    avalanche_argv[av_argc++] = host;
    printf("argv[%d]=%s\n", av_argc - 1, avalanche_argv[av_argc - 1]);
    int port;
    READ(port, int, "d", true);
    char prt[128];
    sprintf(prt, "--port=%d", prt);
    avalanche_argv[av_argc++] = host;
    printf("argv[%d]=%s\n", av_argc - 1, avalanche_argv[av_argc - 1]);    
  }

  int masklength;
  READ(masklength, int, "d", true);
  if (masklength != 0)
  {
    char* mask = new char[masklength];
    if (read(fd, mask, masklength) < 0) conn_error("connection with server is down");
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
    printf("argv[%d]=%s\n", av_argc - 1, avalanche_argv[av_argc - 1]);
  }

  int filtersNum;
  READ(filtersNum, int, "d", true);
  for (int i = 0; i < filtersNum; i++)
  {
    int length;
    char buf[128];
    READ(length, int, "d", true);
    if (read(fd, buf, length) < 0) conn_error("connection with server is down");
    buf[length] = '\0';
    char* fltr = new char[128];
    sprintf(fltr, "--func-name=%s", buf);
    avalanche_argv[av_argc++] = fltr;
    printf("argv[%d]=%s\n", av_argc - 1, avalanche_argv[av_argc - 1]);
  }  

  int flength;
  read(fd, &flength, sizeof(int));
  if (flength != 0)
  {
    char* filter = new char[flength];
    if (read(fd, filter, flength) < 0) conn_error("connection with server is down");
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
    printf("argv[%d]=%s\n", av_argc - 1, avalanche_argv[av_argc - 1]);
  }

  for (int i = 0; i < argsnum; i++)
  {
    int arglength;
    READ(arglength, int, "d", true);
    char* arg = new char[arglength + 1];
    if (read(fd, arg, arglength) < 0) conn_error("connection with server is down");
    arg[arglength] = '\0';
    avalanche_argv[av_argc++] = arg;
    printf("argv[%d]=%s\n", av_argc - 1, avalanche_argv[av_argc - 1]);
  }
  avalanche_argv[av_argc] = NULL;
  printf("argv[%d]=NULL\n", av_argc);

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
    int length, startdepth;
    for (int j = 0; j < file_num; j ++)
    {
      res = read(fd, &length, sizeof(int));
      if (res == -1) conn_error("connection with server is down");
      if (res == 1)
      {
        printf("no data from server\n");
        close(fd);
        for (int i = 0; i < file_name.size(); i ++)
        {
          delete [](file_name.at(i));
        }
        free(avalanche_argv[0]);
        return 0;
      }
      printf("%d\n", length);
      char* file = new char[length];
      received = 0;
      while (received < length)
      {
        res = read(fd, file + received, length - received);
        if (res < 1)
        {
          free(avalanche_argv[0]);
          conn_error("connection with server is down");
        }
        received += res;
      }
      int descr = open(file_name.at(j), O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
      if (descr == -1)
      {
        perror("open failed");
        close(fd);
        for (int i = 0; i < file_name.size(); i ++)
        {
          delete [](file_name.at(i));
        }
        free(avalanche_argv[0]);
        return 0;
      }
      write(descr, file, length);
      close(descr);
      delete[] file;
    }
    READ(startdepth, int, "d", true);
    char sdepth[128];
    sprintf(sdepth, "--startdepth=%d", startdepth);
    avalanche_argv[2 + file_num] = sdepth;
    printf("argv[%d]=%s\n", 2 + file_num, avalanche_argv[2 + file_num]);

    char prefix[128];
    sprintf(prefix, "--prefix=branch%d_", ++runs);
    avalanche_argv[4 + file_num] = prefix;
    printf("argv[%d]=%s\n", 4 + file_num, avalanche_argv[4 + file_num]);    
  }
  close(fd);
  for (int i = 0; i < file_name.size(); i ++)
  {
    delete [](file_name.at(i));
  }
 
  return 0;
}

