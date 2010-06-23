// $Id: TmpFile.cpp 80 2009-10-30 18:55:50Z iisaev $
/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*------------------------------------ TmpFile.cpp ---------------------------------------*/
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
#include "TmpFile.h"

#include <stdlib.h>

#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <set>

using namespace std;

static Logger *logger = Logger::getLogger();

unsigned int TmpFile::tmpnum = 0;

TmpFile::TmpFile(): is_exported(false), is_good(true)
{
    char s[64];
    sprintf(s, "tmpfile_%u", tmpnum++);
    filename = strdup(s);
    FILE *fp = fopen(filename, "wt");
    
    if (!fp) 
    {
        is_good = false;
        ERR(logger, "Cannot open file " << filename << ":" << strerror(errno));
    }
    else
    {
        fclose(fp);
    }
}

TmpFile::~TmpFile()
{
    if (is_exported != true) 
    {
      remove();
    }
    free(filename);
}

void TmpFile::remove()
{
    if (is_good != true) return;

    if (::unlink(filename) == -1)
        ERR(logger, "Cannot delete file " << filename <<":"<< strerror(errno));
}

void TmpFile::print() const
{
    if (is_good != true) return;

    ifstream in_file(filename);

    while (in_file.eof() != true) {
        char buf[65536];

        in_file.getline(buf, 65536);
        DBG(logger, buf);
    }
    in_file.close();
}

