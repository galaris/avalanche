// $Id: PluginExecutor.cpp 63 2009-08-06 17:44:45Z iisaev $
/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*--------------------------------- ProgExecutor.cpp -------------------------------------*/
/*----------------------------------------------------------------------------------------*/

/*
   Copyright (C) 2009 Ildar Isaev
      iisaev@ispras.ru

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
#include "ProgExecutor.h"
#include "TmpFile.h"

#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <vector>
#include <string>

using namespace std;


static Logger *logger = Logger::getLogger();
pid_t pure_pid;
extern pid_t child_pid;


ProgExecutor::ProgExecutor(const vector<string> &cmd)
{
    prog = strdup(cmd[0].c_str());
    args = (char **)calloc(cmd.size(), sizeof(char *)); 
    for (size_t i = 0; i < cmd.size(); i++)
        args[i] = strdup(cmd[i].c_str());
}

int ProgExecutor::run()
{
    if (prog == NULL)
        return NULL;

    LOG(logger, "Running prog");

    TmpFile file_out;
    TmpFile file_err;
        
    redirect_stdout(file_out.getName());
    redirect_stderr(file_out.getName());

    int ret = exec(false);
    pure_pid = child_pid;
    
    if (ret == -1) {
        ERR(logger, "Problem in execution: " << strerror(errno));
        return -1;
    }

    ret = wait();
    if (ret == -1) {
        LOG(logger, "exited on signal");
        return -1;
    }
    
    DBG(logger, "Prog is finished");

    return 0;
}

