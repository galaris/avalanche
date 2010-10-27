// $Id: STP_Executor.cpp 80 2009-10-30 18:55:50Z iisaev $

/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*--------------------------------- STP_Executor.cpp -------------------------------------*/
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
#include "STP_Executor.h"
#include "STP_Input.h"
#include "STP_Output.h"
#include "TmpFile.h"
#include "Monitor.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <pthread.h>

using namespace std;

extern int thread_num;
extern Monitor* monitor;

static Logger *logger = Logger::getLogger();


STP_Executor::STP_Executor(bool debug_full_enable,
                           const string &install_dir):
                               debug_full(debug_full_enable)
{
    prog = strdup((install_dir + "stp").c_str());

    argsnum = 4;

    args = (char **)calloc(argsnum, sizeof(char *));

    args[0] = strdup(prog);
    args[1] = strdup("-p");
}

STP_Output *STP_Executor::run(STP_Input *input, int thread_index)
{
    LOG(logger, "Thread #" << thread_index << ": Running STP");
    
    if (input == NULL) {
        DBG(logger, "No input");
        return NULL;
    }
    args[2] = strdup(input->getFile());

    TmpFile file_out;
    TmpFile file_err;

    redirect_stdout(file_out.getName());
    redirect_stderr(file_err.getName());

    int ret = exec(true);
    monitor->setPID(child_pid, thread_index);
 
    if (ret == -1) {
        ERR(logger, "Problem in execution: " << strerror(errno));
        return NULL;
    }

    ret = wait();
    if (ret == -1) {
        if (!monitor->getKilledStatus())
        {
          ERR(logger, "Problem in waiting: " << strerror(errno));
        }
        return NULL;
    }
    LOG(logger, "Thread #" << thread_index << ": STP is finished.");

    if (ret != 0) {
        LOG(logger, "STP exits with code " << ret);
        return NULL;
    }

    STP_Output *stp_output = new STP_Output;

    stp_output->setFile(file_out.exportFile());

    return stp_output;
}

