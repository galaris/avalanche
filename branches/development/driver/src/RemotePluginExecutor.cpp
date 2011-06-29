/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*----------------------------- RemotePluginExecutor.cpp ---------------------------------*/
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

#include "Logger.h"
#include "RemotePluginExecutor.h"
#include "FileBuffer.h"
#include "ExecutionManager.h"

#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>


using namespace std;

static Logger *logger = Logger::getLogger();

static
void writeToSocket(int fd, const void* b, size_t count)
{
  char* buf = (char*) b;
  size_t sent = 0;
  while (sent < count)
  {
    size_t s = write(fd, buf + sent, count - sent);
    if (s == -1)
    {
      throw "error writing to socket";
    }
    sent += s;
  }
}

static
void readFromSocket(int fd, const void* b, size_t count)
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

static
void readFromSocketToFile(int socket_fd, const char *file_name, 
                          bool guard, bool use_temp_dir)
{
  if (!guard)
  {
    return;
  }
  int length;
  readFromSocket(socket_fd, &length, sizeof(int));
  char * file_buf = (char *)malloc(length);
  readFromSocket(socket_fd, file_buf, length);
  string s_file_name = file_name;
  if (use_temp_dir)
  {
   s_file_name = ExecutionManager::getTempDir() + s_file_name;
  }
  int file_fd = open(s_file_name.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 
                     S_IRUSR | S_IROTH | S_IRGRP | S_IWUSR | S_IWOTH | S_IWGRP);
  write(file_fd, file_buf, length);
  free(file_buf);
}

static
void writeFromFileToSocket(int socket_fd, const char *file_name, 
                           bool guard, bool use_temp_dir)
{
  if (!guard)
  {
    return;
  }
  string s_file_name = file_name;
  if (use_temp_dir)
  {
   s_file_name = ExecutionManager::getTempDir() + s_file_name;
  }
  FileBuffer f(s_file_name);
  writeToSocket(socket_fd, &(f.size), sizeof(int));
  writeToSocket(socket_fd, f.buf, f.size);
}

bool RemotePluginExecutor::checkFlag(const char *flg_name)
{
  for (int i = 0; i < argsnum; i ++)
  {
    if(strstr(args[i], flg_name) != NULL)
    {
      return true;
    }
  }
  return false;
}

RemotePluginExecutor::RemotePluginExecutor(vector<string> &_args, 
                                           int socket_fd, 
                                           vector<char> &to_send, 
                                           Kind _kind, 
                                           std::string _result_dir)
{
  int i;
  remote_fd = socket_fd;
  result_dir = _result_dir;
  argsnum = _args.size();
  args = (char **)calloc (argsnum, sizeof(char *));
  files_to_send = to_send;
  for (i = 0; i < argsnum; i ++)
  {
    args[i] = strdup(_args[i].c_str());
  }
  kind = _kind;
}

int RemotePluginExecutor::run(int thread_index)
{
  int res;
  try
  {
    char util_c;
    char *file_name;
    int i, arg_length, file_length;
    writeToSocket(remote_fd, &kind, sizeof(int));
    writeToSocket(remote_fd, &argsnum, sizeof(int));
    for (i = 0; i < argsnum; i ++)
    {
      arg_length = strlen(args[i]);
      writeToSocket(remote_fd, &arg_length, sizeof(int));
      writeToSocket(remote_fd, args[i], arg_length);
      util_c = files_to_send[i] ? '1' : '\0';
      writeToSocket(remote_fd, &util_c, 1);
      if (util_c)
      {
        char *eq_sign = strchr(args[i], '=');
        if (eq_sign != NULL)
        {
          eq_sign ++;
          file_name = eq_sign;
        }
        else
        {
          file_name = args[i];
        }
        string s_file_name = file_name;
        FileBuffer f(s_file_name);
        writeToSocket(remote_fd, &(f.size), sizeof(int));
        writeToSocket(remote_fd, f.buf, f.size);
      }
    }
    writeFromFileToSocket(remote_fd, "prediction.log", 
                           checkFlag("--check-prediction=yes"), true);
    writeFromFileToSocket(remote_fd, "replace_data", 
                           checkFlag("--replace=yes --replace=replace_data"), 
                           true);
    writeFromFileToSocket(remote_fd, "arg_lengths", 
                           checkFlag("--check-argv="), true);
    readFromSocket(remote_fd, &res, sizeof(int));
    switch (kind)
    {
      case TG: readFromSocketToFile(remote_fd, "trace.log", true, true);
               readFromSocketToFile(remote_fd, "dangertrace.log", 
                                     checkFlag("--check-danger=yes"), true);
               readFromSocketToFile(remote_fd, "actual.log", 
                                     checkFlag("--dump-prediction=yes"), true);
               readFromSocketToFile(remote_fd, 
                                     result_dir.append("calldump.log").c_str(), 
                                     checkFlag("--dump-file=calldump.log"),
                                     false);
               readFromSocketToFile(remote_fd, "replace_data",
                                     checkFlag("--sockets=yes--datagrams=yes"),
                                     true);
               readFromSocketToFile(remote_fd, "argv.log", 
                                     checkFlag("--check-argv="), true);
               break;
      case CV:   
      case MC: readFromSocketToFile(remote_fd, "basic_blocks.log", 
                                     !checkFlag("--no-coverage=yes"), true);
               readFromSocketToFile(remote_fd, "execution.log", true, true);
               break;
      default: throw "unknown plugin"; break;
    }
  }
  catch(...)
  {
    LOG(Logger::NETWORK_LOG, "Connection with remote plugin agent is down");
    return 1;
  }
  return res;
}
