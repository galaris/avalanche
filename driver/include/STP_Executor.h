// $Id: STP_Executor.h 80 2009-10-30 18:55:50Z iisaev $
/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*---------------------------------- STP_Executor.h --------------------------------------*/
/*----------------------------------------------------------------------------------------*/

/*
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

#ifndef __STP_EXECUTOR__H__
#define __STP_EXECUTOR__H__

#include "Executor.h"

#include <string>

class STP_Input;
class STP_Output;


class STP_Executor : public Executor
{
public:
    STP_Executor(bool debug_full_enable, const std::string &install_dir);

    STP_Output *run(STP_Input *input, int thread_index = 0);

private:
    bool debug_full;
};


#endif //__STP_EXECUTOR__H__

