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

#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <iostream>

using namespace std;

static bool distHostSpecified;
static bool distPortSpecified;

OptionParser::OptionParser(int argc, char *argv[])
{
    setProgName(argv[0]);
    for (int i = 1; i < argc; i++)
        args.push_back(string(argv[i]));
}

OptionConfig *OptionParser::run() const
{
    OptionConfig *config = new OptionConfig;
    bool stpThreadsSpecified = false;
    distHostSpecified = false;
    distPortSpecified = false;
    bool fileSpecified = false;
    size_t sl = progName.find_last_of('/');
    if (sl != string::npos) {
        config->setValgrind(progName.substr(0, sl + 1));
    }
    else {
        config->setValgrind("");
    }

    for (size_t i = 0; i < args.size(); i++) {
        if (args[i].find("--filename=") != string::npos) {
            string filename = args[i].substr(strlen("--filename="));
            config->addFile(filename);
            fileSpecified = true;
        }
        else if (args[i].find("--host=") != string::npos) {
            string host = args[i].substr(strlen("--host="));
            config->setHost(host);
        }
        else if (args[i].find("--dist-host=") != string::npos) {
            distHostSpecified = true;
            string host = args[i].substr(strlen("--dist-host="));
            config->setDistHost(host);
        }
        else if (args[i].find("--remote-host=") != string::npos) {
            string host = args[i].substr(strlen("--remote-host="));
            config->setRemoteHost(host);
        }
        else if (args[i].find("--report-log=") != string::npos) {
            string log = args[i].substr(strlen("--report-log="));
            config->setReportLog(log);
        }
        else if (args[i].find("--prefix=") != string::npos) {
            string prefix = args[i].substr(strlen("--prefix="));
            config->setPrefix(prefix);
        }
        else if (args[i].find("--depth=") != string::npos) {
            string depth = args[i].substr(strlen("--depth="));
            if (depth == string("infinity")) {
                config->setDepth(0);
            }
            else {
                config->setDepth(atoi(depth.c_str()));
            }
        }
        else if (args[i].find("--startdepth=") != string::npos) {
            string depth = args[i].substr(strlen("--startdepth="));
            config->setStartdepth(atoi(depth.c_str()));
        }
        else if (args[i].find("--alarm=") != string::npos) {
            string alarm = args[i].substr(strlen("--alarm="));
            config->setAlarm(atoi(alarm.c_str()));
        }
        else if (args[i].find("--func-name=") != string::npos) {
            string name = args[i].substr(strlen("--func-name="));
            config->addFuncFilterUnit(name);
        }
        else if (args[i].find("--func-file=") != string::npos) {
            string fname = args[i].substr(strlen("--func-file="));
            config->setFuncFilterFile(fname);
        }
        else if (args[i].find("--mask=") != string::npos) {
            string fname = args[i].substr(strlen("--mask="));
            config->setInputFilterFile(fname);
        }
        else if (args[i].find("--tracegrind-alarm=") != string::npos) {
            string alarm = args[i].substr(strlen("--tracegrind-alarm="));
            config->setTracegrindAlarm(atoi(alarm.c_str()));
        }
        else if (args[i].find("--port=") != string::npos) {
            string port = args[i].substr(strlen("--port="));
            config->setPort(atoi(port.c_str()));
        }
        else if (args[i].find("--dist-port=") != string::npos) {
            distPortSpecified = true;
            string port = args[i].substr(strlen("--dist-port="));
            config->setDistPort(atoi(port.c_str()));
        }
        else if (args[i].find("--remote-port=") != string::npos) {
            string port = args[i].substr(strlen("--remote-port="));
            config->setRemotePort(atoi(port.c_str()));
        }
        else if (args[i].find("--stp-threads=") != string::npos) {
            string thread_num = args[i].substr(strlen("--stp-threads="));
            if (thread_num == string("auto")) {
                config->setSTPThreadsAuto();
                config->setSTPThreads(sysconf(_SC_NPROCESSORS_ONLN));
            }
            else {
                stpThreadsSpecified = true;
                config->setSTPThreads(atoi(thread_num.c_str()));
            }
        }
        else if (args[i].find("--check-argv=") != string::npos) {
            string argv_mask = args[i].substr(strlen("--check-argv="));
            config->setCheckArgv(argv_mask);
        }
        else if (args[i] == "--debug") {
            config->setDebug();
        }
        else if (args[i] == "--protect-arg-name") {
            config->setProtectArgName();
        }
        else if (args[i] == "--protect-main-agent") {
            config->setProtectMainAgent();
        }
        else if (args[i] == "--distributed") {
            config->setDistributed();
        }
        else if (args[i] == "--remote-valgrind") {
            config->setRemoteValgrind();
        }
        else if (args[i] == "--agent") {
            config->setAgent();
        }
        else if (args[i] == "--check-danger") {
            config->setCheckDanger();
        }
        else if (args[i] == "--trace-children") {
            config->setTraceChildren();
        }
        else if (args[i] == "--suppress-subcalls") {
            config->setSuppressSubcalls();
        }
        else if (args[i] == "--dump-calls") {
            config->setDumpCalls();
        }

        // Verbose options

        else if (args [i] == "--verbose" || args [i] == "-v") {
            config->setVerbose ();
        }
        else if (args[i] == "--program-output") {
            config->setProgramOutput ();
        }
        else if (args[i] == "--network-log") {
            config->setNetworkLog ();
        }

        else if (args[i] == "--use-memcheck") {
            config->setUsingMemcheck();
        }
        else if (args[i] == "--leaks") {
            config->setLeaks();
        }
        else if (args[i] == "--sockets") {
            config->setUsingSockets();
        }
        else if (args[i] == "--datagrams") {
            config->setUsingDatagrams();
        }
        else if (args[i] == "--help") {
            delete config;
            return NULL;
        }
        else {
            // Program name and arguments

            config->addProgAndArg(args[i]);
            for (size_t j = i + 1; j < args.size(); j++)
                config->addProgAndArg(args[j]);
            break;
        }
    }
        if (config->getAgent() && config->getDistributed()) {
        delete config;
        cout << "you cannot specify '--agent' and '--distributed' at the same time\n";
    }

    if (config->usingMemcheck() && config->getDumpCalls()) {
        delete config;
        cout << "'--dump-calls' should be used without '--use-memcheck'\n";
        return NULL;
    }

    if (!fileSpecified && !config->usingSockets() && !config->usingDatagrams() && (config->getCheckArgv() == "")) {
        delete config;
        cout << "no input files or sockets specified and command line option checking is not enabled\n";
        return NULL;
    }
    else if (config->usingSockets() && ((config->getPort() == 65536) || (config->getHost() == ""))) {
        delete config;
        cout << "if '--sockets' option is specified, then IP host address and port number must be also provided\n";
        return NULL;
    }
    else if (fileSpecified && (config->usingSockets() || config->usingDatagrams())) {
        delete config;
        cout << "you cannot specify '--filename' and '--sockets' or '--datagrams' at the same time\n";
        return NULL;
    }
    else if (config->getRemoteValgrind() && (config->getSTPThreads() != 0)){
        delete config;
        cout << "you cannot use remote valgrind plugin agent with STP parallelization enabled\n";
        return NULL;
    }
    reportDummyOptions(config);
    return config;
}

void OptionParser::reportDummyOptions(OptionConfig* config) const
{
    vector <string> dummy_opts;
    if (((config->getHost() != "") || (config->getPort() != 65536)) && !config->usingSockets()) {
        string opt;
        if (config->getPort() != 65536) {
            opt.append(string("'--port' "));
        }
        if (config->getHost() != "") {
            opt.append(string("'--host' "));
        }
        dummy_opts.push_back(opt.append("(you should specify '--sockets')"));
    }
    if (config->getSuppressSubcalls() && (config->getFuncFilterFile() == "") && (config->getFuncFilterUnitsNum() == 0)) {
        dummy_opts.push_back(string("'--suppress-subcalls' (you should specify '--func-filter' or '--func-name')"));
    }
    if (config->checkForLeaks() && !config->usingMemcheck()) {
        dummy_opts.push_back(string("'--leaks' (you should specify '--use-memcheck')"));
    }
    if ((distPortSpecified || distHostSpecified || config->getProtectMainAgent()) && !config->getDistributed()) {
        string opt;
        if (distPortSpecified) {
            opt.append(string("'--dist-port' "));
        }
        if (distHostSpecified) {
            opt.append(string("'--dist-host' "));
        }
        if (config->getProtectMainAgent()) {
            opt.append(string("'--protect-main-agent' "));
        }
        dummy_opts.push_back(opt.append("(you should specify '--distributed')"));
    }
    if (dummy_opts.size()) {
        cout << "several options have no effect:\n";
        for (vector <string>::iterator i = dummy_opts.begin(); i != dummy_opts.end(); i ++) {
            cout << *i << endl;
        }
    }
}

static string findInPath(const string &name)
{
    const char *var = getenv("PATH");
    if (var == NULL || var[0] == '\0') return string();

    string dirs = var;
    for (size_t beginPos = 0; beginPos < dirs.size(); ) {
        size_t colonPos = dirs.find(':', beginPos);
        size_t endPos = (colonPos == string::npos) ? dirs.size() : colonPos;
        string dir = dirs.substr(beginPos, endPos - beginPos);
        string fileName = dir + "/" + name;
        if (access(fileName.c_str(), X_OK) == 0) {
            return fileName;
        }
        beginPos = endPos + 1;
    }

    return string();
}

void OptionParser::setProgName(const string &path)
{
    if (path.find_last_of('/') == string::npos) {
        progName = findInPath(path);
    } else {
        progName = path;
    } 
}
