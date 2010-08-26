// $Id: ExecutionManager.cpp 80 2009-10-30 18:55:50Z iisaev $

/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*------------------------------- ExecutionManager.cpp -----------------------------------*/
/*----------------------------------------------------------------------------------------*/

/*
   Copyright (C) 2009 Ildar Isaev
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


#include "ExecutionManager.h"
#include "Logger.h"
#include "Chunk.h"
#include "OptionConfig.h"
#include "PluginExecutor.h"
#include "ProgExecutor.h"
#include "STP_Executor.h"
#include "STP_Input.h"
#include "STP_Output.h"
#include "FileBuffer.h"
#include "SocketBuffer.h"
#include "Input.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <string>
#include <vector>
#include <deque>
#include <set>
#include <map>
#include <functional>

using namespace std;

time_t tg_time = 0;
bool intg = false;
time_t tg_start;
time_t tg_end;
time_t cv_time = 0;
bool incv = false;
time_t cv_start;
time_t cv_end;
time_t stp_time = 0;
bool instp = false;
time_t stp_start;
time_t stp_end;
time_t pure_time = 0;
bool inpure = false;
time_t pure_start;
time_t pure_end;

extern pid_t child_pid;
bool killed = false;
bool nokill = false;

Logger *logger = Logger::getLogger();
Input* initial;
int allSockets = 0;
int curSockets;
int listeningSocket;
int fifofd;
int memchecks = 0;
Kind kind;
  
vector<Chunk*> report;

ExecutionManager::ExecutionManager(OptionConfig *opt_config)
{
    DBG(logger, "Initializing plugin manager");

    cond_depth  = 1;
    config      = new OptionConfig(opt_config);
    exploits    = 0;
    divergences = 0;
}

int ExecutionManager::checkAndScore(Input* input)
{

  if (config->usingSockets() || config->usingDatagrams())
  {
    input->dumpExploit("replace_data", false);
  }
  else
  {
    input->dumpFiles();
  }

  vector<string> plugin_opts;
  if (config->usingSockets())
  {
    ostringstream cv_host;
    cv_host << "--host=" << config->getHost();
    plugin_opts.push_back(cv_host.str());

    ostringstream cv_port;
    cv_port << "--port=" << config->getPort();
    plugin_opts.push_back(cv_port.str());
    
    plugin_opts.push_back("--replace=replace_data");
    plugin_opts.push_back("--sockets=yes");

    LOG(logger, "setting alarm " << config->getAlarm());
    alarm(config->getAlarm());
    killed = false;
  }
  else if (config->usingDatagrams())
  { 
    plugin_opts.push_back("--replace=replace_data");
    plugin_opts.push_back("--datagrams=yes");

    LOG(logger, "setting alarm " << config->getAlarm());
    alarm(config->getAlarm());
    killed = false;
  }
  else
  {
    ostringstream cv_alarm;
    cv_alarm << "--alarm=" << config->getAlarm();
    plugin_opts.push_back(cv_alarm.str());
  }

  plugin_opts.push_back("--log-file=execution.log");

  PluginExecutor plugin_exe(config->getDebug(), config->getTraceChildren(), config->getValgrind(), config->getProgAndArg(), plugin_opts, kind);
  curSockets = 0;
  cv_start = time(NULL);
  incv = true;
  int exitCode = plugin_exe.run();
  incv = false;
  cv_end = time(NULL);
  cv_time += cv_end - cv_start;
  FileBuffer* mc_output;
  bool infoAvailable = false;
  bool sameExploit = false;
  int exploitGroup = 0;
  if ((exitCode == -1) && !killed)
  {
    FileBuffer* cv_output = new FileBuffer("execution.log");
    bool deleteBuffer = true;
    infoAvailable = cv_output->filterCovgrindOutput();
    if (infoAvailable)
    {
      for (vector<Chunk*>::iterator it = report.begin(); it != report.end(); it++, exploitGroup++)
      {
        if (((*it)->getTrace() != NULL) && (*(*it)->getTrace() == *cv_output))
        {
          sameExploit = true;
          if (config->usingSockets() || config->usingDatagrams())
          {
            (*it)->addGroup(exploits, -1);
          }
          else
          {
            (*it)->addGroup(exploits, input->files.size());
          }
          break;
        }
      }
      if (!sameExploit) 
      {
        Chunk* ch;
        if (config->usingSockets() || config->usingDatagrams())
        {
          ch = new Chunk(cv_output, exploits, -1);
        }
        else
        {
          ch = new Chunk(cv_output, exploits, input->files.size());
        }
        deleteBuffer = false;
        report.push_back(ch);
      }
    }
    else
    {
      Chunk* ch;
      if (config->usingSockets() || config->usingDatagrams())
      {
        ch = new Chunk(NULL, exploits, -1);
      }
      else
      {
        ch = new Chunk(NULL, exploits, input->files.size());
      }
      deleteBuffer = false;
      report.push_back(ch); 
    }
    time_t exploittime;
    time(&exploittime);
    string t = string(ctime(&exploittime));
    REPORT(logger, "Crash detected.");
    LOG(logger, "exploit time: " << t.substr(0, t.size() - 1));  
    if (config->usingSockets() || config->usingDatagrams())
    {
      stringstream ss(stringstream::in | stringstream::out);
      ss << "exploit_" << exploits;
      REPORT(logger, "Dumping an exploit to file " << ss.str());
      input->dumpExploit((char*) ss.str().c_str(), false);
      if (infoAvailable)
      {
        if (!sameExploit)
        {
          stringstream ss(stringstream::in | stringstream::out);
          ss << "stacktrace_" << report.size() - 1 << ".log";
          cv_output->dumpFile((char*) ss.str().c_str());
          REPORT(logger, "Dumping stack trace to file " << ss.str());
        }
        else
        {
          stringstream ss(stringstream::in | stringstream::out);
          ss << "stacktrace_" << exploitGroup << ".log";
          REPORT(logger, "Bug was detected previously. Stack trace can be found in " << ss.str());
        }
      }
      else
      {
        REPORT(logger, "No stack trace is available.");
      }
    }
    else
    {
      if (infoAvailable)
      {
        if (!sameExploit)
        {
          stringstream ss(stringstream::in | stringstream::out);
          ss << "stacktrace_" << report.size() - 1 << ".log";
          cv_output->dumpFile((char*) ss.str().c_str());
          REPORT(logger, "Dumping stack trace to file " << ss.str());
        }
        else
        {
          stringstream ss(stringstream::in | stringstream::out);
          ss << "stacktrace_" << exploitGroup << ".log";
          REPORT(logger, "Bug was detected previously. Stack trace can be found in " << ss.str());
        }
      }
      else
      {
        REPORT(logger, "No stack trace is available.");
      }
      for (int i = 0; i < input->files.size(); i++)
      {
        stringstream ss(stringstream::in | stringstream::out);
        ss << "exploit_" << exploits << "_" << i;
        REPORT(logger, "Dumping an exploit to file " << ss.str());
        input->files.at(i)->FileBuffer::dumpFile((char*) ss.str().c_str());
      }
    }
    exploits++;
    if (deleteBuffer)
    {
      delete cv_output;
    }
  }
  else if (config->usingMemcheck())
  {
    FileBuffer* mc_output = plugin_exe.getOutput();
    char* error = strstr(mc_output->buf, "ERROR SUMMARY: ");
    long errors = -1;
    long definitely_lost = -1;
    long possibly_lost = -1;
    if (error != NULL)
    {
      errors = strtol(error + 15, NULL, 10);
    }
    char* leak = NULL;
    if (config->checkForLeaks())
    {
      leak = strstr(mc_output->buf, "definitely lost: ");
      if (leak != NULL)
      {
        definitely_lost = strtol(leak + 17, NULL, 10);
      }
      leak = strstr(mc_output->buf, "possibly lost: ");
      if (leak != NULL)
      {
        possibly_lost = strtol(leak + 15, NULL, 10);
      }
    }
    if ((errors > 0) || (definitely_lost != -1) && !killed || (possibly_lost != -1) && !killed)
    {
      time_t memchecktime;
      time(&memchecktime);
      string t = string(ctime(&memchecktime));
      REPORT(logger, "Error detected.");
      LOG(logger, "memcheck error time: " << t.substr(0, t.size() - 1));   
      if (config->usingSockets() || config->usingDatagrams())
      {
        stringstream ss(stringstream::in | stringstream::out);
        ss << "memcheck_" << memchecks;
        REPORT(logger, "Dumping input for memcheck error to file " << ss.str());
        input->dumpExploit((char*) ss.str().c_str(), false);
      }
      else
      {
        for (int i = 0; i < input->files.size(); i++)
        {
          stringstream ss(stringstream::in | stringstream::out);
          ss << "memcheck_" << memchecks << "_" << i;
          REPORT(logger, "Dumping input for memcheck error to file " << ss.str());
          input->files.at(i)->FileBuffer::dumpFile((char*) ss.str().c_str());
        }
      }
      memchecks++;  
    }
  }
  int res = 0;
  int fd = open("basic_blocks.log", O_RDWR);
  struct stat fileInfo;
  fstat(fd, &fileInfo);
  int size = fileInfo.st_size / sizeof(int);
  unsigned int* basicBlockAddrs = new unsigned int[size];
  read(fd, basicBlockAddrs, fileInfo.st_size);
  for (int i = 0; i < size; i++)
  {
    if (basicBlocksCovered.insert(basicBlockAddrs[i]).second)
    {
      res++;
    }
  }
  delete[] basicBlockAddrs;
  close(fd);
  return res;
}

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

class cmp: public binary_function<Key, Key, bool>
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

void ExecutionManager::updateInput(Input* input)
{
  int fd = open("replace_data", O_RDWR);
  int socketsNum;
  read(fd, &socketsNum, sizeof(int));
  for (int i = 0; i < socketsNum; i++)
  {
    int chunkSize;
    read(fd, &chunkSize, sizeof(int));
    if (i >= input->files.size())
    {
      input->files.push_back(new SocketBuffer(i, chunkSize));
    }
    else if (input->files.at(i)->size < chunkSize)
    {
      input->files.at(i)->size = chunkSize;
      input->files.at(i)->buf = (char*) realloc(input->files.at(i)->buf, chunkSize);
      memset(input->files.at(i)->buf, 0, chunkSize);
    }
    read(fd, input->files.at(i)->buf, chunkSize);
  }
  close(fd);
}

void alarmHandler(int signo)
{
  LOG(logger, "time is out");
  if (!nokill)
  {
    kill(child_pid, SIGALRM);
    killed = true;
    DBG(logger, "Time out. Valgrind is going to be killed");
  }
  signal(SIGALRM, alarmHandler);
}

void ExecutionManager::run()
{
    DBG(logger, "Running execution manager");
    int runs = 0;
    if (config->usingMemcheck())
    {
      kind = MEMCHECK;
    }
    else
    {
      kind = COVGRIND;
    }

    multimap<Key, Input*, cmp> inputs;
    initial = new Input();
    if (!config->usingSockets() && !config->usingDatagrams())
    {
      for (int i = 0; i < config->getNumberOfFiles(); i++)
      {
        initial->files.push_back(new FileBuffer((char*) config->getFile(i).c_str()));
      }
    }
    else
    {
      signal(SIGALRM, alarmHandler);
    }
    initial->startdepth = 1;
    int score;
    score = checkAndScore(initial);
    LOG(logger, "score=" << score);
    inputs.insert(make_pair(Key(score, 0), initial));

    while (!inputs.empty()) 
    {
      REPORT(logger, "Starting iteration " << runs);
      LOG(logger, "inputs.size()=" << inputs.size());
      multimap<Key, Input*, cmp>::iterator it = --inputs.end();
      Input* fi = it->second;
      unsigned int scr = it->first.score;
      unsigned int dpth = it->first.depth;
      LOG(logger, "selected next input with score " << scr);
      inputs.erase(it);

      if (config->usingSockets() || config->usingDatagrams())
      {
        fi->dumpExploit("replace_data", true);
      }
      else
      {
        fi->dumpFiles();
      }
      ostringstream tg_depth;
      tg_depth << "--startdepth=" << fi->startdepth;
      ostringstream tg_invert_depth;
      tg_invert_depth << "--invertdepth=" << config->getDepth();
   
      vector<string> plugin_opts;
      plugin_opts.push_back(tg_depth.str());
      plugin_opts.push_back(tg_invert_depth.str());

      if (config->getDumpCalls())
      {
        plugin_opts.push_back("--dump-file=calldump.log");
      }
      else
      {
        plugin_opts.push_back("--dump-prediction=yes");
      }

      ostringstream tg_check_danger;
      if (config->getCheckDanger())
      {
        tg_check_danger << "--check-danger=yes";
      }
      else
      {
        tg_check_danger << "--check-danger=no";
      }
      plugin_opts.push_back(tg_check_danger.str());
      for (int i = 0; i < config->getFuncFilterUnitsNum(); i++)
      {
        ostringstream tg_fname;
        tg_fname << "--func-name=" << config->getFuncFilterUnit(i);
        plugin_opts.push_back(tg_fname.str()); 
      }
      if (config->getFuncFilterFile() != "")
      {
        ostringstream tg_func_filter_filename;
        tg_func_filter_filename << "--func-filter-file=" << config->getFuncFilterFile();
        plugin_opts.push_back(tg_func_filter_filename.str());
      }
 
      if (config->getInputFilterFile() != "")
      {
        ostringstream tg_input_filter_filename;
        tg_input_filter_filename << "--mask=" << config->getInputFilterFile();
        plugin_opts.push_back(tg_input_filter_filename.str());
      }

      if (config->getSuppressSubcalls())
      {
        plugin_opts.push_back("--suppress-subcalls=yes");
      }

      if (config->usingSockets())
      {
        ostringstream tg_host;
        tg_host << "--host=" << config->getHost();
        plugin_opts.push_back(tg_host.str());

        ostringstream tg_port;
        tg_port << "--port=" << config->getPort();
        plugin_opts.push_back(tg_port.str());

        plugin_opts.push_back("--replace=yes");
        plugin_opts.push_back("--sockets=yes");
        if (config->getTracegrindAlarm() != 0)
        {
          alarm(config->getTracegrindAlarm());
        }
        killed = false;
      }
      else if (config->usingDatagrams())
      {
        plugin_opts.push_back("--replace=yes");
        plugin_opts.push_back("--datagrams=yes");
        if (config->getTracegrindAlarm() != 0)
        {
          alarm(config->getTracegrindAlarm());
        }
        killed = false;
      }      
      else
      {
        for (int i = 0; i < config->getNumberOfFiles(); i++)
        {
          ostringstream tg_inputfile;
          tg_inputfile << "--file=" << config->getFile(i);
          plugin_opts.push_back(tg_inputfile.str());
        }
      }

      if (runs > 0)
      {
        plugin_opts.push_back("--check-prediction=yes");
      }
      
      PluginExecutor plugin_exe(config->getDebug(), config->getTraceChildren(), config->getValgrind(), config->getProgAndArg(), plugin_opts, TRACEGRIND);
      tg_start = time(NULL);
      intg = true;
      if (config->getTracegrindAlarm() == 0)
      {
        nokill = true;
      }
      int exitCode = plugin_exe.run();
      if (config->getTracegrindAlarm() == 0)
      {      
        nokill = false;
      }
      intg = false;
      tg_end = time(NULL);
      tg_time += tg_end - tg_start;
      if (config->usingSockets() || config->usingDatagrams())
      {
        updateInput(fi);
      }

      if (exitCode == -1)
      {
        LOG(logger, "failure in tracegrind\n");
      }

      int divfd = open("divergence.log", O_RDWR);
      if ((divfd != -1) && config->getDebug() && (runs > 0))
      {
        bool divergence;
        read(divfd, &divergence, sizeof(bool));
        if (divergence)
        {
          int d;
          read(divfd, &d, sizeof(int));
          DBG(logger, "divergence at depth " << d << "\n");

          if (config->usingSockets() || config->usingDatagrams())
          {
            stringstream ss(stringstream::in | stringstream::out);
            ss << "divergence_" << divergences;
            LOG(logger, "dumping divergent input to file " << ss.str());
            fi->parent->dumpExploit((char*) ss.str().c_str(), false);
          }
          else
          {
            for (int i = 0; i < fi->parent->files.size(); i++)
            {
              stringstream ss(stringstream::in | stringstream::out);
              ss << "divergence_" << divergences << "_" << i;
              LOG(logger, "dumping divergent input to file " << ss.str());
              fi->parent->files.at(i)->FileBuffer::dumpFile((char*) ss.str().c_str());
            }
          }
          divergences++;
          DBG(logger, "with startdepth=" << fi->parent->startdepth << " and invertdepth=" << config->getDepth() << "\n");
          close(divfd);
          if (scr == 0) continue;
        }
        else
        {
          close(divfd);
        }
      }
 
      if (config->getDumpCalls())
      {
        break;
      }

      int actualfd = open("actual.log", O_RDWR);
      bool* actual = new bool[fi->startdepth - 1 + config->getDepth()];
      read(actualfd, actual, (fi->startdepth - 1 + config->getDepth()) * sizeof(bool));
      close(actualfd);

      if (config->getCheckDanger())
      {
        FileBuffer dtrace("dangertrace.log");
        char* dquery;
        while ((dquery = strstr(dtrace.buf, "QUERY(FALSE)")) != NULL)
        {
          //dump to the separate file
          unsigned int oldsize = dtrace.size;
          dtrace.size = (dquery - dtrace.buf) + 13;
          //dtrace.dumpFile(".avalanche/curdtrace.log");
          dtrace.dumpFile("curdtrace.log");
          //replace QUERY(FALSE); with newlines
          int k = 0;
          for (; k < 13; k++)
          {
            dquery[k] = '\n';
          }
          k = -1;
          while (dquery[k] != '\n')
          {
            dquery[k] = '\n';
            k--;
          }
          //restore the FileBuffer size
          dtrace.size = oldsize;
          //set up the STP_Input to the newly dumped trace
          STP_Input si;
          //si.setFile(".avalanche/curdtrace.log");
          si.setFile("curdtrace.log");
          //the rest stuff
          STP_Executor stp_exe(config->getDebug(), config->getValgrind());        
          stp_start = time(NULL);
          instp = true;
          nokill = true;
          STP_Output *stp_output = stp_exe.run(&si);
          nokill = false;
          instp = false;
          stp_end = time(NULL);
          stp_time += stp_end - stp_start;
          if (stp_output == NULL)
          {
            ERR(logger, "STP has encountered an error");
            FileBuffer f("curdtrace.log");
            ERR(logger, "curdtrace.log:\n" << string(f.buf));
            continue;
          }
          if (stp_output->getFile() != NULL)
          {
            FileBuffer f(stp_output->getFile());
            DBG(logger, "stp output:\n" << string(f.buf));
            Input* next = new Input();
            for (int i = 0; i < fi->files.size(); i++)
            { 
              FileBuffer* fb = fi->files.at(i)->forkInput(stp_output->getFile());
              if (fb == NULL)
              {
                delete next;
                next = NULL;
                break;
              }
              else
              {
                next->files.push_back(fb);
              }
            }
            if (next != NULL)
            {
              checkAndScore(next);
              delete next;
            }
          }
          delete stp_output;
        }
      }

      FileBuffer trace("trace.log");
      char* query;
      int depth = 0;
      //int rejects = 0;
      while ((query = strstr(trace.buf, "QUERY(FALSE)")) != NULL)
      {
        depth++;
        //invert the last condition
        if (query[-4] == '0')
        {
          query[-4] = '1';
        } 
        else if (query[-4] == '1')
        {
          query[-4] = '0';
        }
        //dump to the separate file
        unsigned int oldsize = trace.size;
        trace.size = (query - trace.buf) + 13;
        //trace.dumpFile(".avalanche/curtrace.log");
        trace.dumpFile("curtrace.log");
        //replace QUERY(FALSE); with newlines
        for (int k = 0; k < 13; k++)
        {
          query[k] = '\n';
        }
        //restore the previously inverted condition
        if (query[-4] == '0')
        {
          query[-4] = '1';
        } 
        else if (query[-4] == '1')
        {
          query[-4] = '0';
        }
        //restore the FileBuffer size
        trace.size = oldsize;
        //set up the STP_Input to the newly dumped trace
        STP_Input si;
        //si.setFile(".avalanche/curtrace.log");
        si.setFile("curtrace.log");
        //the rest stuff
        STP_Executor stp_exe(config->getDebug(), config->getValgrind());        
        stp_start = time(NULL);
        instp = true;
        nokill = true;
        STP_Output *stp_output = stp_exe.run(&si);
        nokill = false;
        instp = false;
        stp_end = time(NULL);
        stp_time += stp_end - stp_start;

        if (stp_output == NULL)
        {
          ERR(logger, "STP has encountered an error");
          FileBuffer f("curtrace.log");
          ERR(logger, "curtrace.log:\n" << string(f.buf));
          continue;
        }
        if (stp_output->getFile() != NULL)
        {
          FileBuffer f(stp_output->getFile());
          DBG(logger, "stp output:\n" << string(f.buf));
          Input* next = new Input();
          for (int i = 0; i < fi->files.size(); i++)
          { 
            FileBuffer* fb = fi->files.at(i)->forkInput(stp_output->getFile());
            if (fb == NULL)
            {
              delete next;
              next = NULL;
              break;
            }
            else
            {
              next->files.push_back(fb);
            }
          }
          if (next != NULL)
          {
            next->startdepth = fi->startdepth + depth;
            bool* prediction = new bool[fi->startdepth - 1 + depth];
            for (int j = 0; j < fi->startdepth + depth - 2; j++)
            {
              prediction[j] = actual[j];
            }
            prediction[fi->startdepth + depth - 2] = !actual[fi->startdepth + depth - 2];
            next->prediction = prediction;
            next->predictionSize = fi->startdepth - 1 + depth;
            next->parent = fi;
            int score;
            score = checkAndScore(next);
            LOG(logger, "score=" << score << "\n");
            inputs.insert(make_pair(Key(score, dpth + depth), next));
          }
        }
        delete stp_output;
      }
      if (depth == 0)
      {
        LOG(logger, "no QUERY's found");
      }
      runs++;
    }
    initial->dumpFiles();
}

ExecutionManager::~ExecutionManager()
{
    DBG(logger, "Destructing plugin manager");

    delete config;
}

