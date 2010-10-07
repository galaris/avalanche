// $Id: PluginExecutor.cpp 80 2009-10-30 18:55:50Z iisaev $
/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*-------------------------------- PluginExecutor.cpp ------------------------------------*/
/*----------------------------------------------------------------------------------------*/
 
/*
   Copyright (C) 2009 Ildar Isaev
      iisaev@ispras.ru
   Copyright (C) 2009 Nick Lugovskoy
      lugovskoy@ispras.ru

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
#include "PluginExecutor.h"
#include "FileBuffer.h"
#include "STP_Input.h"
#include "TmpFile.h"

#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <vector>
#include <string>
#include <pthread.h>

extern pid_t child_pid;
pid_t tg_pid;
pid_t* cv_pid;

extern pthread_mutex_t child_pid_mutex;
extern int thread_num;

using namespace std;


static Logger *logger = Logger::getLogger();


PluginExecutor::PluginExecutor(bool debug_full_enabled,
			       bool traceChildren,
                               const string &install_dir,
                               const vector<string> &cmd,
                               const vector<string> &tg_args,
			       Kind kind): 
                                   debug_full(debug_full_enabled), traceChildren(traceChildren), kind(kind)
{
    if (cmd.size() < 1) {
        LOG(logger, "No program name");
        return;
    }
    prog = strdup((install_dir + "valgrind").c_str());

    // last NULL element is needed by execvp()
    args = (char **)calloc(cmd.size() + tg_args.size() + 4, sizeof(char *)); 

    args[0] = strdup(prog);
    switch (kind)
    {
      case TRACEGRIND: args[1] = strdup("--tool=tracegrind");
                       break;
      case MEMCHECK:   args[1] = strdup("--tool=memcheck");
                       break;      
      case COVGRIND:   args[1] = strdup("--tool=covgrind");
    }

    if (traceChildren)
    {
      args[2] = strdup("--trace-children=yes");
    }
    else
    {
      args[2] = strdup("--trace-children=no");
    }
    
    for (size_t i = 0; i < tg_args.size(); i++)
        args[i + 3] = strdup(tg_args[i].c_str());

    for (size_t i = 0; i < cmd.size(); i++)
        args[i + tg_args.size() + 3] = strdup(cmd[i].c_str());

    output = NULL;
}

int PluginExecutor::run(int thread_index)
{
    if (prog == NULL)
        return NULL;

    LOG(logger, "Running plugin kind=" << kind);

    TmpFile file_out;
    TmpFile file_err;
        
    redirect_stdout(file_out.getName());
    redirect_stderr(file_err.getName());

    if (thread_num > 1)
      pthread_mutex_lock(&child_pid_mutex);
    int ret = exec(false);
    if (kind == TRACEGRIND)
    {
      tg_pid = child_pid;
    }
    else
    {
      cv_pid[thread_index] = child_pid;
    }
    if (thread_num > 1)
      pthread_mutex_unlock(&child_pid_mutex);
    if (ret == -1) 
    {
      ERR(logger, "Problem in execution: " << strerror(errno));
      if (kind == MEMCHECK)
      {
        output = new FileBuffer(file_err.exportFile());
      }
      return -1;
    }

    ret = wait();

    if (ret == -1) 
    {
      LOG(logger, "exited on signal");
      if (kind == MEMCHECK)
      {
        output = new FileBuffer(file_err.exportFile());
      }
      return -1;
    }

    switch (kind)
    {
      case TRACEGRIND: DBG(logger, "Tracegrind is finished");
		       break;
      case MEMCHECK:   DBG(logger, "Memcheck is finished");
                       output = new FileBuffer(file_err.exportFile());
                       break;
      case COVGRIND:   DBG(logger, "Covgrind is finished");
    }

    return 0;
}

FileBuffer* PluginExecutor::getOutput()
{
    return output;
}

PluginExecutor::~PluginExecutor()
{
  if (output != NULL)
  {
    unlink(output->name);
    delete output;
  }  
}

