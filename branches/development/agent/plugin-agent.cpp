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
#include <cstdlib>
#include <vector>
#include <unistd.h>
#include <cstddef>
#include <cerrno>

#include "util.h"

using namespace std;

enum Kind
{
  TG,
  CV,
  MC,
  UNID
};

#define DEBUG

int avalanche_fd;
pid_t pid = 0;
Kind kind;
bool no_coverage;
bool check_prediction;
bool dump_prediction;
bool check_danger;
bool dump_calls;
bool network;
bool check_argv;
string temp_dir;

static bool parseArg(char *arg)
{
  if (!strcmp(arg, "--no-coverage=yes"))
  {
    no_coverage = true;
  }
  else if (!strcmp(arg, "--check-prediction=yes"))
  {
    check_prediction = true;
  }
  else if (!strcmp(arg, "--dump-prediction=yes"))
  {
    dump_prediction = true;
  }
  else if (!strcmp(arg, "--check-danger=yes"))
  {
    check_danger = true;
  }
  else if (!strcmp(arg, "--dump-file=calldump.log"))
  {
    dump_calls = true;
  }
  else if (!strcmp(arg, "--sockets=yes") || !strcmp(arg, "--datagrams=yes"))
  {
    network = true;
  }
  else if (strstr(arg, "--check-argv="))
  {
    check_argv = true;
  }
  else if (strstr(arg, "--temp-dir="))
  {
    temp_dir = string(strchr(arg, '=') + 1);
    if (mkdir(temp_dir.c_str(), S_IRWXU | S_IRWXG | S_IRWXO) < 0)
    {
      if (errno != EEXIST)
      {
        perror((string("cannot create ") + temp_dir).c_str());
        temp_dir = "";
      }
    }
    return false;
  }
  return true;
}

static void readToFile(const char *file_name)
{
  int length, i = 0;
  char c;
  readFromSocket(avalanche_fd, &length, sizeof(int));
  int file_d = open(file_name, O_CREAT | O_TRUNC | O_WRONLY, 
                    S_IRUSR | S_IROTH | S_IRGRP | S_IWUSR | S_IWOTH | S_IWGRP);
  if (file_d < 0)
  {
    throw file_name;
  }
  while (i < length)
  {
    readFromSocket(avalanche_fd, &c, 1);
    if (write(file_d, &c, 1) < 1)
    {
      close(file_d);
      throw "error writing to file";
    }
    i ++;
  }
  close(file_d);
}
      

static int readAndExec(const string &progDir, int argc, char** argv)
{
  int length, argsnum;
  char **args;
  char util_c;
  no_coverage = false;
  readFromSocket(avalanche_fd, &kind, sizeof(int));
  if (kind == UNID)
  {
    return -2;
  }
  readFromSocket(avalanche_fd, &argsnum, sizeof(int));
  args = (char **) calloc (argsnum + 3, sizeof(char *));
  string valgrindPath = progDir + "../lib/avalanche/valgrind";
  args[0] = strdup(valgrindPath.c_str());

  switch(kind)
  {
    case TG: args[1] = strdup("--tool=tracegrind"); 
             break;
    case CV: args[1] = strdup("--tool=covgrind"); 
             break;
    case MC: args[1] = strdup("--tool=memcheck"); 
             break;
    default: break;
  }
  for (int i = 2; i < argsnum + 2; i ++)
  {
    readFromSocket(avalanche_fd, &length, sizeof(int));
    args[i] = (char *) malloc(length + 1);
    readFromSocket(avalanche_fd, args[i], length);
    args[i][length] = '\0';
    if (!parseArg(args[i]) && (kind == CV))
    {
      argsnum --;
      i --;
    }
    readFromSocket(avalanche_fd, &util_c, 1);
    if (util_c)
    {
      char * file_name = strchr(args[i], '=');
      if (file_name == NULL)
      {
        file_name = args[i];
      }
      else
      {
        file_name ++;
      }
      readToFile(file_name);
    }
  }
  if (check_prediction)
  {
    readToFile(string(temp_dir).append("prediction.log").c_str());
  }
  if (network)
  {
    readToFile(string(temp_dir).append("replace_data").c_str());
  }
  if (check_argv)
  {
    readToFile(string(temp_dir).append("arg_lengths").c_str());
  }
  args[argsnum + 2] = NULL;
  pid = fork();
  if (pid == 0)
  {
#ifdef DEBUG
    cout << endl << "executing command: " << endl;
    for (int i = 0; i < argsnum + 2; i ++)
    {
      cout << args[i] << " ";
    }
    cout << endl;
#endif
    int tmpout_fd = open("tmp_stdout", O_CREAT | O_TRUNC | O_WRONLY,
                         S_IRUSR | S_IROTH | S_IRGRP | S_IWUSR | S_IWOTH | S_IWGRP);
    int tmperr_fd = open("tmp_stderr", O_CREAT | O_TRUNC | O_WRONLY,
                         S_IRUSR | S_IROTH | S_IRGRP | S_IWUSR | S_IWOTH | S_IWGRP);
    dup2(tmpout_fd, STDOUT_FILENO);
    dup2(tmperr_fd, STDERR_FILENO);
    execvp(args[0], args);
  }
  int status;
  pid_t ret_proc = ::waitpid(pid, &status, 0);
#ifdef DEBUG
  cout << "plugin finished work";
#endif
  if (ret_proc == (pid_t)(-1)) 
  {
    return 1;
  }
  for (int i = 0; i < argsnum + 2; i ++)
  {
    free(args[i]);
  }
  free(args);
#ifdef DEBUG
  if (!WIFEXITED(status))
  {
    cout << " (crashed)" << endl;
  }
  else 
  {
    cout << endl;
  }
#endif
  if ((WEXITSTATUS(status) == 126) ||
      (WEXITSTATUS(status) == 127)) //Problem with executable
  {
    int fd = open("tmp_stderr", O_RDONLY, S_IRUSR);
    lseek(fd, SEEK_SET, 0);
    struct stat f_stat;
    fstat(fd, &f_stat);
    char buf[f_stat.st_size + 1];
    read(fd, buf, f_stat.st_size);
    buf[f_stat.st_size] = '\0';
    cout << buf << endl;
    return 1;
  }
  return ((WIFEXITED(status)) ? 0 : -1);
}

static void writeFromFile(const char *file_name)
{
  int file_d = open(file_name, O_RDONLY, S_IRWXG | S_IRWXO | S_IRWXU);
  if (file_d < 0)
  {
    throw file_name;
  }
  struct stat file_info;
  if (fstat(file_d, &file_info) < 0)
  {
    close(file_d);
    throw "fstat failed";
  }
  int size = file_info.st_size;
  char c;
  int i = 0;
  writeToSocket(avalanche_fd, &size, sizeof(int));
  while(i < size)
  {
    if (read(file_d, &c, 1) < 1)
    {
      close(file_d);
      throw "error reading from file";
    }
    writeToSocket(avalanche_fd, &c, 1);
    i ++;
  }
  close(file_d);
}

static int passResult(int ret_code)
{
  writeToSocket(avalanche_fd, &ret_code, sizeof(int));
  if (ret_code == 1)
  {
    return -1;
  }
  switch(kind)
  {
    case TG: writeFromFile(string(temp_dir).append("trace.log").c_str());
             if (check_danger)
             {
               writeFromFile(string(temp_dir).append("dangertrace.log").c_str());
             }
             if (dump_prediction)
             {
               writeFromFile(string(temp_dir).append("actual.log").c_str());
             }
             if (dump_calls)
             {
               writeFromFile("calldump.log");
             }
             if (network)
             {
               writeFromFile(string(temp_dir).append("replace_data").c_str());
             }
             if (check_argv)
             {
               writeFromFile(string(temp_dir).append("argv.log").c_str());
             }
             break;
    case CV:
    case MC: if (!no_coverage)
             {
               writeFromFile(string(temp_dir).append("basic_blocks.log").c_str());
             }
             writeFromFile(string(temp_dir).append("execution.log").c_str());
             break;
    default: break;
  }
  return 0;
}

static string findInPath(const string &name)
{
  const char *var = getenv("PATH");
  if (var == NULL || var[0] == '\0') return string();

  string dirs = var;
  for (size_t beginPos = 0; beginPos < dirs.size(); ) {
    size_t colonPos = dirs.find(':', beginPos);
    size_t endPos = (colonPos == string::npos) ? dirs.size() : colonPos;
    string dir = dirs.substr(beginPos, endPos - beginPos);
    string fileName = dir + "/" + name;
    if (access(fileName.c_str(), X_OK) == 0) {
      return fileName;
    }
    beginPos = endPos + 1;
  }

  return string();
}

int main(int argc, char** argv)
{
  if (argc != 2)
  {
    cout << "usage: plugin-agent <port number>" << endl;
    exit(EXIT_FAILURE);
  }
  temp_dir = "";
  string progName = argv[0];
  size_t slashPos = progName.find_last_of('/');
  if (slashPos == string::npos) {
    progName = findInPath(progName);
    slashPos = progName.find_last_of('/');
  }
  string progDir = progName.substr(0, slashPos + 1);

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

  try {
    int size = sizeof(long);
    writeToSocket(avalanche_fd, &size, sizeof(int));
    while(1)
    {
      no_coverage = false;
      dump_prediction = false;
      check_prediction = false;
      check_danger = false;
      dump_calls = false;
      network = false;
      check_argv = false;
      int res = readAndExec(progDir, argc, argv);
      if (res == -2)
      {
        cout << "end of communication: no more requests" << endl;
        break;
      }
      if (passResult(res) < 0)
      {
        break;
      }
    }
  }
  catch(const char * error_msg)
  {
    cout << "end of communication: " << error_msg << endl;
  }
  shutdown(avalanche_fd, SHUT_RDWR);
  unlink("tmp_stdout");
  unlink("tmp_stderr");
  unlink(string(temp_dir).append("trace.log").c_str());
  unlink(string(temp_dir).append("dangertrace.log").c_str());
  unlink(string(temp_dir).append("actual.log").c_str());
  unlink(string(temp_dir).append("arg_lengths").c_str());
  unlink(string(temp_dir).append("replace_data").c_str());
  unlink(string(temp_dir).append("prediction.log").c_str());

  /* STP multi-threading currently cannot be used in split mode */
  
  /* We don't pass thread number with options so we don't know which
       files were created and have to use exec */
       
  //system((string("rm ") + temp_dir + string("replace_data*")).c_str());
  
  /* We have argv.log_i with multiple threads for STP since argv.log
       is treated like an input file specified by '--filename=' */
       
  //system((string("rm ") + temp_dir + string("argv.log*")).c_str());
  //system((string("rm ") + temp_dir + string("basic_blocks*.log")).c_str());
  if (temp_dir != "")
  {
    if (rmdir(temp_dir.c_str()) < 0)
    {
      if (errno != ENOENT)
      {
        perror((string("cannot delete ") + temp_dir).c_str());
      }
    }
  }
  return 0;
}
    
