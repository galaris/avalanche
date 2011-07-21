/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*------------------------------------- Error.cpp ----------------------------------------*/
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

#include "Error.h"
#include "Logger.h"

#include <cerrno>
#include <cstring>

using namespace std;

enum {
    PLAIN,
    VERBOSE,
    ERROR_LOG
};

static Logger* logger = Logger::getLogger();

static const char* error_pattern[] = {
                "SIGSEGV",
                "SIGABRT",
                "SIGALRM",
                "SIGFPE",
                "uninitialised",
                "Invalid read",
                "Invalid free",
                "Mismatched",
                "are definitely lost",
                "are possibly lost",
                NULL
};


static const char* error_name[] = { 
                "Segmentation fault",
                "Aborted",
                "Exited due to alarm",
                "Floating point exception",
                "Use of unitialised values",
                "Invalid read/write",
                "Invalid free",
                "Use of mismatched memory allocation/deallocation functions",
                "Definite memory leak",
                "Possible memory leak",
                NULL
};

Error::Error(unsigned int _id, int _input, string _trace, int _error_type) :
    id(_id), trace(_trace), error_type(_error_type)
{
    inputs.push_back(_input);
}

Error::Error(unsigned int _id, int _input, int _error_type) : 
    id(_id), error_type(_error_type)
{
    inputs.push_back(_input);
}

Error::~Error()
{
}

void Error::setTrace(string _trace)
{
    trace = _trace;
}

std::string Error::getTrace()
{
    return trace;
}

std::string Error::getTraceBody()
{
    unsigned int endl_pos = trace.find("\n");
    if (endl_pos != string::npos)
    {
        return trace.substr(endl_pos + 1);
    }
    return string("");
}

void Error::setCommand(string _command)
{
    command = _command;
}

void Error::updateCommand(string _command)
{
    all_command += _command + string("\n");
}

string Error::getCommand()
{
    return command;
}

void Error::setTraceFile(string _trace_file)
{
    trace_file = _trace_file;
}

string Error::getTraceFile()
{
    return trace_file;
}

void Error::addInput(int _input)
{
    inputs.push_back(_input);
}

string Error::getSummary(string prefix, int input_num, bool verbose)
{
    string input_file_m;
    if (Error::isExploit(error_type))
    {
        input_file_m = prefix + string("exploit_");
    }
    else if (Error::isMemoryError(error_type))
    {
        input_file_m = prefix + string("memcheck_");
    }
    ostringstream out_stream;
    out_stream << endl << " Error #" << id << ": ";
    out_stream << Error::getErrorName(error_type) << endl;
    if (input_num != 0)
    {
        out_stream << "  Inputs: ";
    }
    for (vector <int>::iterator it = inputs.begin();
                                it != inputs.end();
                                it ++)
    {

        if (it == inputs.begin())
        {
            out_stream << "  ";
        }
        if (input_num < 0)
        {
            out_stream << input_file_m << *it;
        }
        else if (input_num > 0)
        {
            for (int i = 0; i < input_num; i ++)
            {
                out_stream << input_file_m << *it << "_" << i;
                if (i < input_num - 1)
                {
                    out_stream << ", ";
                }
            }
        }
        else
        {
            break;
        }
        if (verbose)
        {
            out_stream << endl;
        }
        else
        {
            out_stream << "; ";
        }
    }
    out_stream << endl;
    if (verbose)
    {
        out_stream << " Stack trace";
        if (trace == "")
        {
            out_stream << " unavailable";
        }
        else
        {
            out_stream << ":" << endl << "  " << trace << endl;
        }
    }
/*    else
    {
        out_stream << "- " << trace_file << endl;
    }*/
    out_stream << "  Command: " << command << endl;
    return out_stream.str();
}

string Error::getList()
{
    ostringstream out_stream;
    out_stream << trace << endl;
    out_stream << all_command << endl << endl;
    return out_stream.str();
}

string Error::getErrorName()
{
    unsigned int endl_pos = trace.find("\n");
    if (endl_pos != string::npos)
    {
        return trace.substr(0, endl_pos);
    }
    return string("");
}

string Error::getErrorName(unsigned int error_type)
{
    if (Error::isExploit(error_type) || 
        Error::isMemoryError(error_type))
    {
        return string(error_name[error_type]);
    }
    return string("");
}

int Error::getErrorType(string error_name)
{
    int i = 0;
    while(error_pattern[i] != NULL)
    {
        if (error_name.find(error_pattern[i]) != string::npos)
        {
            return i;
        }
        i ++;
    }
    return -1;
}

bool Error::isExploit(unsigned int error_type)
{
    return ((error_type >= CRASH_SIGSEGV) && 
            (error_type <= CRASH_SIGFPE));
}

bool Error::isMemoryError(unsigned int error_type)
{
    return ((error_type >= MC_UNINIT) &&
            (error_type <= MC_POSS_LOST));
}
