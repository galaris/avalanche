/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*----------------------------------- STP_Output.cpp -------------------------------------*/
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
#include "STP_Output.h"

#include <unistd.h>
#include <errno.h>
#include <set>
#include <string>
#include <stdlib.h>

static Logger *logger = Logger::getLogger();

STP_Output::~STP_Output()
{
    if (unlink(file) == -1)
    {
        ERR(logger, "Cannot delete file " << file <<":"<< strerror(errno));
    }
    if (file != NULL)
    {
      free(file);
    }
}

