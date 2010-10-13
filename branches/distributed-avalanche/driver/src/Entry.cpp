// $Id: Entry.cpp 81 2009-10-30 19:22:11Z iisaev $

/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*------------------------------------- Entry.cpp ----------------------------------------*/
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

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <set>
#include <signal.h>
#include <dirent.h>

#include "ExecutionManager.h"
#include "Logger.h"
#include "FileBuffer.h"
#include "OptionConfig.h"
#include "OptionParser.h"
#include "Input.h"
#include "Chunk.h"
#include "Thread.h"
#include "Monitor.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstdlib>
#include <string.h>
#include <cerrno>

using namespace std;

static Logger *logger = Logger::getLogger();
Monitor* monitor;

time_t start;
time_t end;

ExecutionManager* em;

extern PoolThread *threads;
extern Input* initial;
extern vector<Chunk*> report;

extern pthread_cond_t finish_cond;

extern set <int> modified_input;

int thread_num;

static void printHelpBanner()
{
    char banner[] =
        "usage: avalanche [options] prog-and-args\n\n"
        "  user options defined in [ ]:\n"
        "    --help                       print help and exit\n"
        "    --use-memcheck               use memcheck instead of covgrind\n"
        "    --leaks                      check for memory leaks\n"
        "                                 (ignored if '--use-memcheck' isn't specified)\n"
        "    --verbose                    much more detailed avalanche output\n" 
        "    --debug                      save some debugging information - divergent inputs, etc.\n" 
        "    --depth=<number>             the number of conditions inverted during one run of\n"
        "                                 tracegrind (default is 100)\n"
        "    --alarm=<number>             timer value in seconds (for infinite loop recognition) (default is 300)\n"
        "    --filename=<input_file>      the path to the file with the input data for the application being tested\n"
        "    --trace-children             run valgrind plugins with '--trace-children=yes' option\n"
        "    --check-danger               emit special constraints for memory access operations\n"
	"                                 and divisions (slows down the analysis)\n"
	"    --dump-calls                 dump the list of functions manipulating with tainted data to calldump.log\n"
	"    --func-name=<name>           the name of function that should be used for separate function analysis\n"
	"    --func-file=<name>           the path to the file with the list of functions that\n"
	"                                 should be used for separate function analysis\n"
	"    --mask=<mask_file>           the path to the file with input mask\n"
	"    --suppress-subcalls          ignore conditions in a nested function calls during separate analysis\n"
        "\n"
        "  special options for sockets:\n"
        "    --sockets                    mark data read from TCP sockets as tainted\n"
        "    --host=<IPv4 address>        IP address of the network connection (for TCP sockets only)\n"
        "    --port=<number>              port number of the network connection (for TCP sockets only)\n"
        "    --datagrams                  mark data read from UDP sockets as tainted\n"
        "    --alarm=<number>             timer for breaking infinite waitings in covgrind\n"
        "                                 or memcheck (not set by default)\n" 
        "    --tracegrind-alarm=<number>  timer for breaking infinite waitings in tracegrind (not set by default)\n"; 

    std::cout << banner << std::endl;
}

OptionConfig* opt_config;

void clean_up()
{
  delete monitor;
  if (thread_num > 0)
  {
    for (int i = 1; i < thread_num + 1; i ++)
    {
      ostringstream file_modifier;
      file_modifier << "_" << i;
      remove(string("basic_blocks").append(file_modifier.str()).append(".log").c_str());
      remove(string("execution").append(file_modifier.str()).append(".log").c_str());
      remove(string("prediction").append(file_modifier.str()).append(".log").c_str());
      remove(string("curtrace").append(file_modifier.str()).append(".log").c_str());
      for (set <int>::iterator j = modified_input.begin(); j != modified_input.end(); j ++)
      {
        string f_name = string((opt_config->getProgAndArg())[*j]);
        remove(f_name.append(file_modifier.str()).c_str());
      }
    }
    delete []threads;
  }
}

void sig_hndlr(int signo)
{
  initial->dumpFiles();
  monitor->setKilledStatus(true);
  for (int i = 0; i < thread_num; i ++)
  {
    if (!threads[i].getStatus())
    {
      threads[i].waitForThread();
    }
  }
  monitor->handleSIGKILL();
  end = time(NULL);
  char s[256];
  sprintf(s, "total: %ld, ", end - start);
  LOG(logger, "Time statistics:\n" << s << monitor->getStats(end - start));
  REPORT(logger, "\nExploits report:");
  for (int i = 0; i < report.size(); i++)
  {
    report.at(i)->print(opt_config->getPrefix(), i);
  }
  REPORT(logger, "");
  clean_up();
  exit(0);
  
}

int main(int argc, char *argv[])
{
    start = time(NULL); 
    signal(SIGINT, sig_hndlr);
    LOG(logger, "start time: " << std::string(ctime(&start)));    
    OptionParser  opt_parser(argc, argv);
    opt_config = opt_parser.run();

    if (opt_config == NULL || opt_config->empty()) {
        printHelpBanner();
        return EXIT_FAILURE;
    }

    if (opt_config->getVerbose()) logger->enableVerbose();

    thread_num = opt_config->getSTPThreads();
    string checker_name = ((opt_config->usingMemcheck()) ? string("memcheck") : string("covgrind"));
    if (thread_num > 0)
    {
      monitor = new ParallelMonitor(checker_name, thread_num, start);
      threads = new PoolThread[thread_num];
    }
    else
    {
      monitor = new SimpleMonitor(checker_name);
    }
    time_t starttime;
    time(&starttime);

    LOG(logger, "Avalanche, a dynamic analysis tool.");
  
    string t = string(ctime(&starttime));
    LOG(logger, "Start time: " << t.substr(0, t.size() - 1));  

    ExecutionManager manager(opt_config);
    em = &manager;
    //delete(opt_config);
    manager.run();
    end = time(NULL);
    char s[256];
    sprintf(s, "total: %ld, ", end - start);
    LOG(logger, "Time statistics:\n" << s << monitor->getStats(end - start));
    initial->dumpFiles();
    REPORT(logger, "\nExploits report:");
    for (int i = 0; i < report.size(); i++)
    {
      report.at(i)->print(opt_config->getPrefix(), i);
    }
    REPORT(logger, "");
    clean_up();
    return EXIT_SUCCESS;
}

