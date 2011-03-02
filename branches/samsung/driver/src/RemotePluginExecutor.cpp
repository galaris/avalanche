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

#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>


using namespace std;

static Logger *logger = Logger::getLogger();

static int writeBuffer(int socket_fd, int length, char *buf)
{
  int sent = 0, res;
  while (sent < length)
  {
    res = write(socket_fd, buf + sent, length - sent);
    if (res <= 0)
    {
      return 1;
    }
    sent += res;
  }
  return 0;
}

static int readBuffer(int socket_fd, int length, char *buf)
{
  int received = 0, res;
  while (received < length)
  {
    res = read(socket_fd, buf + received, length - received);
    if (res <= 0)
    {
      return 1;
    }
    received += res;
  }
  return 0;
}

static int readBufferToFile(int socket_fd, int length, char *file_name)
{
  char * file_buf = (char *)malloc(length);
  readBuffer(socket_fd, length, file_buf);
  int file_fd = open(file_name, O_CREAT | O_TRUNC | O_WRONLY, S_IRWXU | S_IRWXG | S_IRWXO);
  write(file_fd, file_buf, length);
  free(file_buf);
  return 0;
}

RemotePluginExecutor::RemotePluginExecutor(vector<string> &_args, int socket_fd, vector<char> &to_send, Kind _kind)
{
  int i;
  remote_fd = socket_fd;
  argsnum = _args.size();
  args = (char **)calloc (argsnum, sizeof(char *));
  files_to_send = to_send;
  for (i = 0; i < argsnum; i ++)
  {
    args[i] = strdup(_args[i].c_str());
  }
  kind = _kind;
}

int RemotePluginExecutor::run()
{
  char util_c;
  char *file_name;
  int i, res, arg_length, file_length;
  bool no_coverage = false;
  bool check_prediction = false;
  bool dump_prediction = false;
  write(remote_fd, &kind, sizeof(int));
  write(remote_fd, &argsnum, sizeof(int));
  for (i = 0; i < argsnum; i ++)
  {
    arg_length = strlen(args[i]);
    write(remote_fd, &arg_length, sizeof(int));
    res = writeBuffer(remote_fd, arg_length, args[i]);
    util_c = files_to_send[i] ? '1' : '\0';
    write(remote_fd, &util_c, 1);
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
      FileBuffer f(file_name);
      write(remote_fd, &(f.size), sizeof(int));
      writeBuffer(remote_fd, f.size, f.buf);
    }
  }
  if (check_prediction)
  {
    FileBuffer f("prediction.log");
    write(remote_fd, &(f.size), sizeof(int));
    writeBuffer(remote_fd, f.size, f.buf);
  }
  read(remote_fd, &res, sizeof(int));
  switch (kind)
  {
    case TRACEGRIND: read(remote_fd, &file_length, sizeof(int));
                     readBufferToFile(remote_fd, file_length, "trace.log");
                     if (dump_prediction)
                     {
                       read(remote_fd, &file_length, sizeof(int));
                       readBufferToFile(remote_fd, file_length, "actual.log");
                     }
                     break;
    case COVGRIND:   
    case MEMCHECK:   if (!no_coverage)
                     {
                       read(remote_fd, &file_length, sizeof(int));
                       readBufferToFile(remote_fd, file_length, "basic_blocks.log");
                     }
                     read(remote_fd, &file_length, sizeof(int));
                     readBufferToFile(remote_fd, file_length, "execution.log");
                     break;
    default:         break;
  }
  return res;
}
