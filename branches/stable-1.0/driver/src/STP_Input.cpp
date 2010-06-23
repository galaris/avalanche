// $Id: STP_Input.cpp 80 2009-10-30 18:55:50Z iisaev $
/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*----------------------------------- STP_Input.cpp --------------------------------------*/
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
#include "STP_Input.h"

#include <cstdio>

using namespace std;


bool STP_Input::isEmpty()
{
    FILE *fp = fopen(getFile(), "rt");
    if (!fp) return true;

    bool ret = false;

    fseek(fp, 0, SEEK_END);
    if (ftell(fp) == 0) ret = true;
    fclose(fp);

    return ret;
}

