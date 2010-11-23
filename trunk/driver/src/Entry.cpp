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

ExecutionManager* em;
OptionParser *op;

extern PoolThread *threads;
extern Input* initial;
extern vector<Chunk*> report;

extern int in_thread_creation;

int thread_num;
extern int distfd;

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

    cout << banner << endl;
}

OptionConfig* opt_config;

void cleanUp()
{
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
      remove(string("replace_data").append(file_modifier.str()).c_str());
      for (int j = 0; j < opt_config->getNumberOfFiles(); j ++)
      {
        remove(opt_config->getFile(j).append(file_modifier.str()).c_str());
      }
    }
    delete []threads;
  }
  for (int i = 0; i < report.size(); i ++)
  {
    delete (report.at(i));
  }
  delete em;
  delete op;
  delete opt_config;
  delete initial;
  delete monitor;
  delete logger;
}

void reportResults()
{
  time_t end_time = time(NULL);
  LOG(logger, "Time statistics:\ntotal: " << end_time - monitor->getGlobalStartTime() << ", "
                                          << monitor->getStats(end_time - monitor->getGlobalStartTime()));
  if (opt_config->getReportLog() == string(""))
  {
    REPORT(logger, "\nExploits report:");
    for (int i = 0; i < report.size(); i++)
    {
      report.at(i)->print(opt_config->getPrefix(), i);
    }
    REPORT(logger, "");
  }
  else
  {
    int fd = open(opt_config->getReportLog().c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    for (int i = 0; i < report.size(); i++)
    {
      report.at(i)->print(opt_config->getPrefix(), i, fd);
    }
    close(fd);
  }  
}

void sig_hndlr(int signo)
{
  if (opt_config->getDistributed())
  {
    write(distfd, "q", 1);
    shutdown(distfd, SHUT_RDWR);
    close(distfd);
  }
  if (!(opt_config->usingSockets()) && !(opt_config->usingDatagrams()))
  {
    initial->dumpFiles();
  }
  monitor->setKilledStatus(true);
  monitor->handleSIGKILL();
  for (int i = 0; i < thread_num; i ++)
  {
    if (in_thread_creation != i)
    {
      threads[i].waitForThread();
    }
  }
  reportResults();
  cleanUp();
  exit(0);
}

int main(int argc, char *argv[])
{
    time_t start_time = time(NULL); 
    signal(SIGINT, sig_hndlr);
    signal(SIGPIPE, SIG_IGN);
    op = new OptionParser(argc, argv);
    opt_config = op->run();
    
    if (opt_config == NULL || opt_config->empty()) {
        printHelpBanner();
        return EXIT_FAILURE;
    }

    if (opt_config->getVerbose()) logger->enableVerbose();

    thread_num = opt_config->getSTPThreads();
    string checker_name = ((opt_config->usingMemcheck()) ? string("memcheck") : string("covgrind"));
    if (thread_num > 0)
    {
      monitor = new ParallelMonitor(checker_name, start_time, thread_num);
      ((ParallelMonitor*)monitor)->setAlarm(opt_config->getAlarm(), opt_config->getTracegrindAlarm());
      threads = new PoolThread[thread_num];
    }
    else
    {
      monitor = new SimpleMonitor(checker_name, start_time);
    }
    checker_name.clear();
    time_t work_start_time = time(NULL);

    LOG(logger, "Avalanche, a dynamic analysis tool.");
    LOG(logger, "Start time: " << ctime(&work_start_time));
  
    em = new ExecutionManager(opt_config);
    em->run();
    if (!(opt_config->usingSockets()) && !(opt_config->usingDatagrams()))
    {
      initial->dumpFiles();
    }
    reportResults();
    cleanUp();
    return EXIT_SUCCESS;
}

