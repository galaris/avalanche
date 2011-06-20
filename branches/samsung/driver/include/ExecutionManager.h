// $Id: ExecutionManager.h 80 2009-10-30 18:55:50Z iisaev $
/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*-------------------------------- ExecutionManager.h ------------------------------------*/
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

#ifndef __EXECUTION_MANAGER__H__
#define __EXECUTION_MANAGER__H__

#include <cstddef>
#include <string>
#include <map>
#include <set>
#include <vector>
#include <functional>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

class FileBuffer;
class OptionConfig;
class Input;

class Key
{
public:
  unsigned int score;
  unsigned int depth;
  
  Key(unsigned int score, unsigned int depth)
  {
    this->score = score;
    this->depth = depth;
  }
};

class cmp: public std::binary_function<Key, Key, bool>
{
public:
  result_type operator()(first_argument_type k1, second_argument_type k2)
  {
    if (k1.score < k2.score)
    {
      return true;
    }
    else if (k1.score > k2.score)
    {
      return false;
    }
    else
    {
      if (k1.depth > k2.depth)
      {
        return true;
      }
      else
      {
        return false;
      }
    }
  }
};

class ExecutionManager
{
public:
    ExecutionManager(OptionConfig *opt_config);

    void run();

    void emulateClient();

    void emulateServer();

    void setupServer();

    void makefifo();
   
    void cleanfifo();

    int processQuery(Input* first_input, bool* actual, unsigned long first_depth, unsigned long cur_depth, unsigned int thread_index = 0);

    int processTraceSequental(Input* first_input, unsigned long first_depth);
    int processTraceParallel(Input* first_input, unsigned long first_depth);

    int requestNonZeroInput();

    void getTracegrindOptions(std::vector <std::string> &plugin_opts);
    void getCovgrindOptions(std::vector <std::string> &plugin_opts, std::string fileNameModifier, bool addNoCoverage);

    int calculateScore(std::string filaNameModifier = "");
    int checkAndScore(Input* input, bool addNoCoverage, bool first_run, bool use_remote, std::string fileNameModifier = "");

    void dumpExploit(Input* input, FileBuffer* stack_trace, bool info_available, bool same_exploit, int exploit_group);
    bool dumpMCExploit(Input* input, const char* exec_log);
    void dumpExploitArgv();

    bool updateArgv(Input* input);

    int checkDivergence(Input* first_input, int score);

    void updateInput(Input* input);

    void talkToServer();

    OptionConfig* getConfig() { return config; }

    ~ExecutionManager();

private:
    OptionConfig *config;
    std::multimap<Key, Input*, cmp> inputs;
    std::vector <std::string> cur_argv;
    std::set<unsigned long> delta_basicBlocksCovered;
    std::set<unsigned long> basicBlocksCovered;
    int exploits;
    int divergences;
};


#endif //__EXECUTION_MANAGER__H__

