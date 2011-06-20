/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*------------------------------------ Logger.cpp ----------------------------------------*/
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

#include "Logger.h"

#include <string>
#include <iostream>

using namespace std;


static Logger *logger = NULL;


Logger *Logger::getLogger()
{
    if (logger == NULL) logger = new Logger;
    return logger;
}

void Logger::write(Level level, const string &msg,
                   const char *file, size_t line) const
{
    switch (level) {
    case LEV_ALWAYS:
        cout << msg << endl;
        break;
    case LEV_NET:
        if (enable_verbose) {
            cout << "NETWORK: "<< msg << endl;
        }
        break;
    case LEV_INFO:
        if (enable_verbose) {
            cout << "INFO: "<< msg << endl;
        }
        break;
    case LEV_DEBUG:
        if (enable_verbose) {
            cout << "DEBUG: " << /*file << ":" << line << "]: " << */msg << endl;
        }
        break;
    case LEV_ERROR:
        if (enable_verbose) {
            cout << "ERROR: [" << file << ":" << line << "]: " << msg << endl;
        }
        break;
    default:
        cout << "Unknown logging level, log message: " << msg << endl;
    }
}

