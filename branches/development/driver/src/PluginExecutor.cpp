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
#include "TmpFile.h"
#include "Monitor.h"

#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <vector>
#include <string>

extern int thread_num;
extern Monitor* monitor;

using namespace std;

static Logger *logger = Logger::getLogger();


PluginExecutor::PluginExecutor(bool debug_full_enabled,
                               bool trace_children,
                               const string &install_dir,
                               const vector<string> &cmd,
                               const vector<string> &tg_args, 
                               Kind kind) : debug_full(debug_full_enabled),
                                            trace_children(trace_children),
                                            kind(kind)
{
    if (cmd.size() < 1) {
        LOG(Logger :: ERROR, "No program name");
        return;
    }
    prog = strdup((install_dir + "../lib/avalanche/valgrind").c_str());

    // last NULL element is needed by execvp()
    argsnum = cmd.size() + tg_args.size() + 4;
    args = (char **)calloc(cmd.size() + tg_args.size() + 4, sizeof(char *)); 

    args[0] = strdup(prog);
    switch (kind)
    {
        case TG: args[1] = strdup("--tool=tracegrind");
                 break;
        case MC: args[1] = strdup("--tool=memcheck");
                 break;      
        case CV: args[1] = strdup("--tool=covgrind");
                 break;
        default: break;
    }

    if (trace_children)
    {
        args[2] = strdup("--trace-children=yes");
    }
    else
    {
        args[2] = strdup("--trace-children=no");
    }
    
    for (size_t i = 0; i < tg_args.size(); i++)
    {
        args[i + 3] = strdup(tg_args[i].c_str());
    }

    for (size_t i = 0; i < cmd.size(); i++)
    {
        args[i + tg_args.size() + 3] = strdup(cmd[i].c_str());
    }

}

int PluginExecutor::run(int thread_index)
{
    if (prog == NULL)
        return NULL;

    string plugin_name = "Unknown";

    switch (kind)
    {
        case TG: plugin_name = "Tracegrind"; 
                 break;
        case MC: plugin_name = "Memcheck"; 
                 break;
        case CV: plugin_name = "Covgrind";
                 break;
        default: break;
    }

    if (!thread_num)
    {
        LOG(Logger::DEBUG, "Running plugin " << plugin_name << ".");
    }
    else
    {
        LOG(Logger::DEBUG, "Thread #" << thread_index << 
                           ": Running plugin " << plugin_name << ".");
    }

    TmpFile* file_out = new TmpFile();
    if (!file_out->good())
    {
        return -1;
    }
    TmpFile* file_err = new TmpFile();
    if (!file_err->good())
    {
        return -1;
    }
    monitor->setTmpFiles(file_out, file_err);
        
    redirect_stdout(file_out->getName());
    redirect_stderr(file_err->getName());

    int ret = exec(false);
    monitor->setPID(child_pid, thread_index);
    if (ret == -1) 
    {
      LOG(Logger :: ERROR, "Problem in execution: " << strerror(errno));
      return -1;
    }

    ret = wait();

    if (ret == -1) 
    {
        if (!monitor->getKilledStatus())
        {
            LOG(Logger :: DEBUG, "Exited on signal.");
            return -1;
        }
        else
        {
            return 0;
        }
    }
    else if (ret == 1)
    {
        return 1;
    }
    ostringstream msg;
    if (thread_num)
    {
        msg << "Thread #" << thread_index << ": ";
    }
      
    switch (kind)
    {
        case TG: LOG(Logger :: DEBUG, msg.str().append("Tracegrind is finished."));
                 break;
        case MC: LOG(Logger :: DEBUG, msg.str().append("Memcheck is finished."));
                 break;
        case CV: LOG(Logger :: DEBUG, msg.str().append("Covgrind is finished."));
                 break;
        default: break;
    }

    return 0;
}

PluginExecutor::~PluginExecutor()
{  
}

