// $Id: ExecutionManager.h 80 2009-10-30 18:55:50Z iisaev $
/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*-------------------------------- ExecutionManager.h ------------------------------------*/
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

#ifndef __EXECUTION_MANAGER__H__
#define __EXECUTION_MANAGER__H__

#include <cstddef>
#include <string>
#include <set>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


class OptionConfig;
class Input;

class ExecutionManager
{
public:
    ExecutionManager(OptionConfig *opt_config);

    void run();

    void emulateClient();

    void emulateServer();

    void setupServer();

    void makefifo();
   
    void cleanfifo();

    int checkAndScore(Input* input);

    void updateInput(Input* input);

    void runUninstrumented(Input* input);

    ~ExecutionManager();

private:
    OptionConfig *config;
    std::size_t   cond_depth;
    std::set<unsigned int> basicBlocksCovered;
    int exploits;
    int divergences;
};


#endif //__EXECUTION_MANAGER__H__

