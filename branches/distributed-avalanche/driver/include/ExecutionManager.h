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

    int runSTPAndCGParallel(bool trace_kind, std::multimap<Key, Input*, cmp> * inputs, Input* first_input, unsigned int first_depth);
    int checkAndScore(Input* input, bool addNoCoverage, const char* fileNameModifier = "", bool first_run = false);

    void dumpExploit(Input* input, FileBuffer* stack_trace, bool info_available, bool same_exploit, int exploit_group);
    bool dumpMCExploit(Input* input, const char* exec_log);

    void updateInput(Input* input);

    void talkToServer(std::multimap<Key, Input*, cmp>& inputs);

    OptionConfig* getConfig() { return config; }

    ~ExecutionManager();

private:
    OptionConfig *config;
    std::size_t   cond_depth;
    std::set<unsigned long> basicBlocksCovered;
    int exploits;
    int divergences;
    int distfd;
};


#endif //__EXECUTION_MANAGER__H__

