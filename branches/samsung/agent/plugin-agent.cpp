/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------------------------- Remote valgrind agent for Avalanche. -------------------------*/
/*---------------------------------- plugin-agent.cpp ------------------------------------*/
/*----------------------------------------------------------------------------------------*/

/*
   Copyright (C) 2011 Michael Ermakov
      mermakov@ispras.ru

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
 
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <cstdlib>
#include <cstring>
#include <cstdio>

#include <vector>

#include "util.h"

using namespace std;

enum Kind
{
  TRACEGRIND,
  COVGRIND,
  MEMCHECK
};

int avalanche_fd;
pid_t pid = 0;
Kind kind;
bool no_coverage;
bool check_prediction;
bool dump_prediction;

static int readAndExec(int argc, char** argv)
{
  int length, argsnum;
  char **args;
  char util_c;
  no_coverage = false;
  readFromSocket(avalanche_fd, &kind, sizeof(int));
  readFromSocket(avalanche_fd, &argsnum, sizeof(int));
  args = (char **) calloc (argsnum + 3, sizeof(char *));

  string argstr(argv[0]);
  size_t sl = argstr.find_last_of('/');
  if (sl != string::npos) 
  {
    args[0] = strdup((char*) (argstr.substr(0, sl + 1) + string("valgrind")).c_str());
  }
  else 
  {
    args[0] = "valgrind";
  }
  argstr.clear();

  switch(kind)
  {
    case TRACEGRIND: args[1] = strdup("--tool=tracegrind"); 
                     break;
    case COVGRIND:	 args[1] = strdup("--tool=covgrind"); 
                     break;
    case MEMCHECK:	 args[1] = strdup("--tool=memcheck"); 
                     break;
    default:	     break;
  }
  for (int i = 2; i < argsnum + 2; i ++)
  {
    readFromSocket(avalanche_fd, &length, sizeof(int));
    args[i] = (char *) malloc(length + 1);
    readFromSocket(avalanche_fd, args[i], length);
    args[i][length] = '\0';
    if (!strcmp(args[i], "--no-coverage=yes"))
    {
      no_coverage = true;
    }
    if (!strcmp(args[i], "--check-prediction=yes"))
    {
      check_prediction = true;
    }
    if (!strcmp(args[i], "--dump-prediction=yes"))
    {
      dump_prediction = true;
    }
    readFromSocket(avalanche_fd, &util_c, 1);
    if (util_c)
    {
      readFromSocket(avalanche_fd, &length, sizeof(int));
      char * file_name = strchr(args[i], '=');
      if (file_name == NULL)
      {
        file_name = args[i];
      }
      else
      {
        file_name ++;
      }
      char *file_buf = (char *) malloc(length);
      readFromSocket(avalanche_fd, file_buf, length);
      int file_d = open(file_name, O_CREAT | O_TRUNC | O_WRONLY, S_IRWXU | S_IRWXG | S_IRWXG);
      write(file_d, file_buf, length);
      close(file_d);
      free(file_buf);
    }
  }
  if (check_prediction)
  {
    readFromSocket(avalanche_fd, &length, sizeof(int));
    char *file_buf = (char *) malloc(length);
    readFromSocket(avalanche_fd, file_buf, length);
    int file_d = open("prediction.log", O_CREAT | O_TRUNC | O_WRONLY, S_IRWXU | S_IRWXG | S_IRWXG);
    write(file_d, file_buf, length);
    close(file_d);
    free(file_buf);
  }
  args[argsnum + 2] = NULL;
  for (int i = 0; i < argsnum + 2; i ++)
  {
    cout << args[i] << " ";
  }
  cout << endl;
  pid = fork();
  if (pid == 0)
  {
    cout << "redirecting stdout and stderr" << endl << "starting plugin" << endl;
    int tmpout_fd = open("tmp_stdout", O_CREAT | O_TRUNC | O_WRONLY, S_IRWXG | S_IRWXU | S_IRWXO);
    int tmperr_fd = open("tmp_stderr", O_CREAT | O_TRUNC | O_WRONLY, S_IRWXG | S_IRWXU | S_IRWXO);
    dup2(tmpout_fd, STDOUT_FILENO);
    dup2(tmperr_fd, STDERR_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    execvp(args[0], args);
  }
  int status;
  pid_t ret_proc = ::waitpid(pid, &status, 0);
  cout << "plugin finished work" << endl;
  //if (ret_proc == (pid_t)(-1)) return -1;
  for (int i = 0; i < argsnum + 2; i ++)
  {
    free(args[i]);
  }
  free(args);
  return ((WIFEXITED(status)) ? 0 : -1);
}

static void passFile(const char *file_name)
{
  int file_d = open(file_name, O_RDONLY, S_IRWXG | S_IRWXO | S_IRWXU);
  struct stat file_info;
  fstat(file_d, &file_info);
  int size = file_info.st_size;
  char *buf = (char*) malloc (size);
  read(file_d, buf, size);
  writeToSocket(avalanche_fd, &size, sizeof(int));
  writeToSocket(avalanche_fd, buf, size);
  free(buf);
}

static int passResult(int ret_code)
{
  writeToSocket(avalanche_fd, &ret_code, sizeof(int));
  switch(kind)
  {
    case TRACEGRIND: passFile("trace.log");
                     if (dump_prediction)
                     {
                       passFile("actual.log");
                     }
                     break;
    case COVGRIND:
    case MEMCHECK:   if (!no_coverage)
                     {
                       passFile("basic_blocks.log");
                     }
                     passFile("execution.log");
                     break;
    default:         break;
  }
  return 0;
}

int main(int argc, char** argv)
{
  if (argc != 2)
  {
    cout << "usage: plugin-agent <port number>" << endl;
    exit(EXIT_FAILURE);
  }
  int port = atoi(argv[1]);
 
  int listen_fd;
  struct sockaddr_in stSockAddr;
  listen_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(listen_fd == -1)
  {
    perror("can not create socket");
    exit(EXIT_FAILURE);
  }

  int on = 1;
  setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
 
  memset(&stSockAddr, 0, sizeof(struct sockaddr_in));
  stSockAddr.sin_family = AF_INET;  
  stSockAddr.sin_port = htons(port);
  stSockAddr.sin_addr.s_addr = INADDR_ANY;

  if(bind(listen_fd, (const struct sockaddr*)&stSockAddr, sizeof(struct sockaddr_in)) < 0)
  {
    perror("bind failed");
    close(listen_fd);
    exit(EXIT_FAILURE);
  }

  if(listen(listen_fd, 10) < 0)
  {
    perror("listen failed");
    close(listen_fd);
    exit(EXIT_FAILURE);
  }

  avalanche_fd = accept(listen_fd, NULL, NULL);
  if (avalanche_fd < 0)
  {
    perror("accept failed");
    close(listen_fd);
    exit(EXIT_FAILURE);
  }
  close(listen_fd);

  int size = sizeof(long);
  writeToSocket(avalanche_fd, &size, sizeof(int));
 
  try {
    while(1)
    {
      no_coverage = false;
      dump_prediction = false;
      check_prediction = false;
      int res = readAndExec(argc, argv);
      passResult(res);
    }
  }
  catch(...)
  {
    cout << "end of communication" << endl;
  }
  unlink("tmp_stdout");
  unlink("tmp_stderr");
  return 0;
}
    
