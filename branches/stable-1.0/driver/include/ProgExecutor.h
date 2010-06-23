// $Id: PluginExecutor.h 63 2009-08-06 17:44:45Z iisaev $
/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*---------------------------------- ProgExecutor.h --------------------------------------*/
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

#ifndef __PROG_EXECUTOR__H__
#define __PROG_EXECUTOR__H__

#include "Executor.h"

#include <cstddef>
#include <vector>
#include <string>


class ProgExecutor : public Executor
{
public:
    ProgExecutor(const std::vector<std::string> &cmd);

    int run();
};


#endif //__PROG_EXECUTOR__H__

