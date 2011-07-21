/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*-------------------------------------- Error.h -----------------------------------------*/
/*----------------------------------------------------------------------------------------*/

/*
   Copyright (C) 2010-2011 Ildar Isaev
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

#ifndef __ERROR__H__
#define __ERROR__H__

#include <vector>
#include <string>

enum {
    /* Exploits */
    CRASH_SIGSEGV,      /* received SIGSEGV */
    CRASH_SIGABRT,      /* received SIGABRT XXX: no stack trace */
    CRASH_SIGALRM,      /* reveived SIGALRM */
    CRASH_SIGFPE,       /* received SIGFPE */

    /* Memchecks */
    MC_UNINIT,          /* Use of uninitialized values */
    MC_INVALID_RW,      /* Invalid read/write */
    MC_INVALID_FREE,    /* Invalid free */
    MC_INVALID_MEM,     /* Mismatched alloc/free */
    MC_DEF_LOST,        /* Definite leak */
    MC_POSS_LOST,       /* Possible leak */

    UNKNOWN
};

class Error
{
private:
    unsigned int id;
    std::string trace;
    std::vector<int> inputs;
    std::string command;
    std::string all_command;
    unsigned int error_type;
    std::string trace_file;

public:
    Error(unsigned int _id, int _input, std::string _trace, int _error_type);
    Error(unsigned int _id, int _input, int _error_type);
    ~Error();

    std::string getSummary(std::string prefix, int input_num, bool verbose);
    std::string getList();

    void setCommand(std::string _command);
    void updateCommand(std::string _command);
    std::string getCommand();

    void setTrace(std::string _trace);
    std::string getTrace();
    std::string getTraceBody();

    void setTraceFile(std::string _trace_file);
    std::string getTraceFile();
    
    void addInput(int input);

    std::string getErrorName();

    static std::string getErrorName(unsigned int error_type);
    static int getErrorType(std::string error_name);
    static bool isExploit(unsigned int error_type);
    static bool isMemoryError(unsigned int error_type);
};

#endif

