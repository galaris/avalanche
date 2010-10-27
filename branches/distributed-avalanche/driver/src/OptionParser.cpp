// $Id: OptionParser.cpp 80 2009-10-30 18:55:50Z iisaev $
/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*--------------------------------- OptionParser.cpp -------------------------------------*/
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

#include "OptionParser.h"
#include "OptionConfig.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

using namespace std;


OptionParser::OptionParser(int argc, char *argv[])
{
    for (int i = 0; i < argc; i++)
        arg_vec.push_back(string(argv[i]));
}

OptionConfig *OptionParser::run() const
{
    OptionConfig *config = new OptionConfig;
    bool fileSpecified = false;
    size_t sl = arg_vec[0].find_last_of('/');
    if (sl != string::npos) {
        config->setValgrind(arg_vec[0].substr(0, sl + 1));
    }
    else {
        config->setValgrind("");
    }

    for (size_t i = 1; i < arg_vec.size(); i++) {
        if (arg_vec[i].find("--filename=") != string::npos) {
            string filename = arg_vec[i].substr(strlen("--filename="));
            config->addFile(filename);
            fileSpecified = true;
        }
        else if (arg_vec[i].find("--host=") != string::npos) {
            string host = arg_vec[i].substr(strlen("--host="));
            config->setHost(host);
        }
        else if (arg_vec[i].find("--prefix=") != string::npos) {
            string prefix = arg_vec[i].substr(strlen("--prefix="));
            config->setPrefix(prefix);
        }
        else if (arg_vec[i].find("--dist-host=") != string::npos) {
            string host = arg_vec[i].substr(strlen("--dist-host="));
            config->setDistHost(host);
        }
        else if (arg_vec[i].find("--depth=") != string::npos) {
            string depth = arg_vec[i].substr(strlen("--depth="));
            config->setDepth(atoi(depth.c_str()));
        }
        else if (arg_vec[i].find("--startdepth=") != string::npos) {
            string depth = arg_vec[i].substr(strlen("--startdepth="));
            config->setStartdepth(atoi(depth.c_str()));
        }
        else if (arg_vec[i].find("--alarm=") != string::npos) {
            string alarm = arg_vec[i].substr(strlen("--alarm="));
            config->setAlarm(atoi(alarm.c_str()));
        }
        else if (arg_vec[i].find("--func-name=") != string::npos) {
            string name = arg_vec[i].substr(strlen("--func-name="));
            config->addFuncFilterUnit(name);
        }
        else if (arg_vec[i].find("--func-file=") != string::npos) {
            string fname = arg_vec[i].substr(strlen("--func-file="));
            config->setFuncFilterFile(fname);
        }
        else if (arg_vec[i].find("--mask=") != string::npos) {
            string fname = arg_vec[i].substr(strlen("--mask="));
            config->setInputFilterFile(fname);
        }
        else if (arg_vec[i].find("--tracegrind-alarm=") != string::npos) {
            string alarm = arg_vec[i].substr(strlen("--tracegrind-alarm="));
            config->setTracegrindAlarm(atoi(alarm.c_str()));
        }
        else if (arg_vec[i].find("--port=") != string::npos) {
            string port = arg_vec[i].substr(strlen("--port="));
            config->setPort(atoi(port.c_str()));
        }
        else if (arg_vec[i].find("--dist-port=") != string::npos) {
            string port = arg_vec[i].substr(strlen("--dist-port="));
            config->setDistPort(atoi(port.c_str()));
        }
        else if (arg_vec[i].find("--stp-threads=") != string::npos) {
            string thread_num = arg_vec[i].substr(strlen("--stp-threads="));
            config->setSTPThreads(atoi(thread_num.c_str()));
        }
        else if (arg_vec[i] == "--debug") {
            config->setDebug();
        }
        else if (arg_vec[i] == "--distributed") {
            config->setDistributed();
        }
        else if (arg_vec[i] == "--agent") {
            config->setAgent();
        }
        else if (arg_vec[i] == "--check-danger") {
            config->setCheckDanger();
        }
        else if (arg_vec[i] == "--trace-children") {
            config->setTraceChildren();
        }
        else if (arg_vec[i] == "--suppress-subcalls") {
            config->setSuppressSubcalls();
        }
        else if (arg_vec[i] == "--dump-calls") {
            config->setDumpCalls();
        }
        else if (arg_vec[i] == "--verbose") {
            config->setVerbose();
        }
        else if (arg_vec[i] == "--use-memcheck") {
            config->setUsingMemcheck();
        }
        else if (arg_vec[i] == "--leaks") {
            config->setLeaks();
        }
        else if (arg_vec[i] == "--sockets") {
            config->setUsingSockets();
        }
        else if (arg_vec[i] == "--datagrams") {
            config->setUsingDatagrams();
        }
        else if (arg_vec[i] == "--help") {
            delete config;
            return NULL;
        }
        else
            config->addProgAndArg(arg_vec[i]);
    }

    if (!fileSpecified && !config->usingSockets() && !config->usingDatagrams()) {
        delete config;
        printf("no input files or sockets specified\n");
        return NULL;
    }
    else if (config->usingSockets() && ((config->getPort() == 65536) || (config->getHost() == ""))) {
        delete config;
        printf("if '--sockets' option is specified, then IP host address and port number must be also provided\n");
        return NULL;
    }
    else if (fileSpecified && (config->usingSockets() || config->usingDatagrams())) {
        delete config;
        printf("you cannot specify '--filename' and '--sockets' or '--datagrams' at the same time\n");
        return NULL;
    }   

    return config;
}

