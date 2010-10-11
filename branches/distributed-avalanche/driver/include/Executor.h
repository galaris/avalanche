// $Id: Executor.h 80 2009-10-30 18:55:50Z iisaev $
/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*------------------------------------- Executor.h ---------------------------------------*/
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

#ifndef __EXECUTOR__H__
#define __EXECUTOR__H__

#include <cstdlib>


class Executor
{
public:
    Executor(): prog(NULL), args(NULL), file_out(-1), file_err(-1)
    {}

    int exec(bool setlimit);

    int wait();

    void redirect_stdout(char *filename);
    
    void redirect_stderr(char *filename);

    ~Executor()
    { 
      if (file_out != -1) 
      {
        close(file_out);
      }
      if (file_err != -1) 
      {
        close(file_err);
      }
    }

protected:
    char  *prog;
    char **args;
    pid_t child_pid;

private:
    void do_redirect(int file_to_redirect, int with_file);

    int file_out;
    int file_err;
};


#endif //__EXECUTOR__H__

