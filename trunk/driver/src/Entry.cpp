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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstdlib>
#include <string.h>
#include <cerrno>

using namespace std;

static Logger *logger = Logger::getLogger();

time_t start;
time_t end;

ExecutionManager* em;

extern time_t tg_time;
extern time_t tg_start;
extern time_t tg_end;
extern time_t cv_time;
extern time_t cv_start;
extern time_t cv_end;
extern time_t stp_time;
extern time_t stp_start;
extern time_t stp_end;
extern time_t pure_time;
extern time_t pure_start;
extern time_t pure_end;
extern bool intg;
extern bool incv;
extern bool instp;
extern bool inpure;
extern pid_t tg_pid, cv_pid, stp_pid, pure_pid;
extern Input* initial;

static void printHelpBanner()
{
    char banner[] =
        "usage: avalanche [options] prog-and-args\n\n"
        "  user options defined in [ ]:\n"
        "    --help                       print help and exit\n"
        "    --use-memcheck               indicate that memcheck should be used instead of covgrind\n"
        "    --leaks                      indicate that inputs resulting in memory leaks should be saved\n"
        "                                 (ignored if '--use-memcheck' isn't specified)\n"
        "    --debug                      more verbous avalanche output\n" 
        "    --depth=<number>             the number of conditions inverted during one run of"
        "                                 tracegrind (default is 100)\n"
        "    --alarm=<number>             timer value in seconds (for infinite loop recognition) (default is 300)\n"
        "    --filename=<input_file>      the path to the file with the input data for the application being tested\n"
        "\n"
        "  special options for sockets:\n"
        "    --sockets                    mark data read from TCP sockets as tainted\n"
        "    --host=<IPv4 address>        IP address of the network connection (for TCP sockets only)\n"
        "    --port=<number>              port number of the network connection (for TCP sockets only)\n"
        "    --datagrams                  mark data read from UDP sockets as tainted\n"
        "    --alarm=<number>             timer for breaking infinite waitings in covgrind"
        "                                 or memcheck (not set by default)\n" 
        "    --tracegrind-alarm=<number>  timer for breaking infinite waitings in tracegrind (not set by default)\n"; 

    std::cout << banner << std::endl;
}


void sig_hndlr(int signo)
{
  if (instp)
  {
    kill(stp_pid, SIGKILL);
    stp_end = time(NULL);
    stp_time += stp_end - stp_start;
  }
  else if (intg)
  {
    kill(tg_pid, SIGKILL);
    tg_end = time(NULL);
    tg_time += tg_end - tg_start;
  }
  else if (incv)
  {
    kill(cv_pid, SIGKILL);
    cv_end = time(NULL);
    cv_time += cv_end - cv_start;
  }
  else if (inpure)
  {
    kill(pure_pid, SIGKILL);
    pure_end = time(NULL);
    pure_time += pure_end - pure_start;
  }
  end = time(NULL);
  char s[256];
  sprintf(s, "totally: %ld, tracegrind: %ld, STP: %ld, covgrind: %ld, pure exec: %ld", end - start, tg_time, stp_time, cv_time, pure_time);
  LOG(logger, "\nTime statistics:\n" << s);
  sprintf(s, "tg_per: %f stp_per: %f cv_per: %f pure_per: %f", ((double) tg_time) / (end - start), ((double) stp_time) / (end - start), ((double) cv_time) / (end - start), ((double) pure_time) / (end - start));
  LOG(logger, s);
  initial->dumpFiles();
  exit(0);
}

int main(int argc, char *argv[])
{
    start = time(NULL); 
    signal(SIGINT, sig_hndlr);
    LOG(logger, "start time: " << std::string(ctime(&start)));    
    OptionParser  opt_parser(argc, argv);
    OptionConfig *opt_config = opt_parser.run();

    if (opt_config == NULL || opt_config->empty()) {
        printHelpBanner();
        return EXIT_FAILURE;
    }

    if (opt_config->getDebug()) logger->enableDebug();
    
    LOG(logger, "Avalanche, a dynamic analysis tool.");

    ExecutionManager manager(opt_config);
    em = &manager;
    delete(opt_config);
    
    manager.run();
    end = time(NULL);
    char s[256];
    sprintf(s, "totally: %ld, tracegrind: %ld, STP: %ld, covgrind: %ld, pure exec: %ld", end - start, tg_time, stp_time, cv_time, pure_time);
    LOG(logger, "\nTime statistics:\n" << s);
    sprintf(s, "tg_per: %f stp_per: %f cv_per: %f pure_per: %f", ((double) tg_time) / (end - start), ((double) stp_time) / (end - start), ((double) cv_time) / (end - start), ((double) pure_time) / (end - start));
    LOG(logger, s);
    initial->dumpFiles();
    return EXIT_SUCCESS;
}

