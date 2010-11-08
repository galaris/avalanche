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
#include "STP_Executor.h"
#include "STP_Input.h"
#include "STP_Output.h"
#include "FileBuffer.h"
#include "SocketBuffer.h"
#include "Input.h"
#include "Thread.h"
#include "Monitor.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <string>
#include <vector>
#include <set>

using namespace std;

extern Monitor* monitor;

PoolThread *threads;
extern int thread_num;

bool killed = false;
bool nokill = false;

bool trace_kind;

Logger *logger = Logger::getLogger();
Input* initial;
int allSockets = 0;
int curSockets;
int listeningSocket;
int fifofd;
int memchecks = 0;
Kind kind;
bool is_distributed = false;

set <unsigned long> delta_bb_covered;
  
vector<Chunk*> report;

set <int> modified_input;

pthread_mutex_t add_inputs_mutex;
pthread_mutex_t add_exploits_mutex;
pthread_mutex_t add_bb_mutex;
pthread_mutex_t add_time_mutex;
pthread_mutex_t finish_mutex;
pthread_cond_t finish_cond;

int in_thread_creation = -1;

int distfd;

ExecutionManager::ExecutionManager(OptionConfig *opt_config)
{
    DBG(logger, "Initializing plugin manager");

    cond_depth  = 1;
    config      = new OptionConfig(opt_config);
    exploits    = 0;
    divergences = 0;
    is_distributed = opt_config->getDistributed();
    if (is_distributed)
    {
      struct sockaddr_in stSockAddr;
      int res;
 
      memset(&stSockAddr, 0, sizeof(struct sockaddr_in));
 
      stSockAddr.sin_family = AF_INET;
      stSockAddr.sin_port = htons(opt_config->getDistPort());
      res = inet_pton(AF_INET, opt_config->getDistHost().c_str(), &stSockAddr.sin_addr);
 
      if (res < 0)
      {
        perror("error: first parameter is not a valid address family");
        exit(EXIT_FAILURE);
      }
      else if (res == 0)
      {
        perror("char string (second parameter does not contain valid ipaddress");
        exit(EXIT_FAILURE);
      }

      distfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

      if (distfd == -1)
      {
        perror("cannot create socket");
        exit(EXIT_FAILURE);
      }
    
      res = connect(distfd, (const struct sockaddr*)&stSockAddr, sizeof(struct sockaddr_in));
 
      if (res < 0)
      {
        perror("error connect failed");
        close(distfd);
        exit(EXIT_FAILURE);
      }  

      LOG(logger, "Connected to server");
      write(distfd, "m", 1);
   }
}

void ExecutionManager::dumpExploit(Input *input, FileBuffer* stack_trace, bool info_available, bool same_exploit, int exploitGroup)
{
  time_t exploittime;
  time(&exploittime);
  string t = string(ctime(&exploittime));
  REPORT(logger, "Crash detected.");
  LOG(logger, "exploit time: " << t.substr(0, t.size() - 1));  
  if (config->usingSockets() || config->usingDatagrams())
  {
    stringstream ss(stringstream::in | stringstream::out);
    ss << config->getPrefix() << "exploit_" << exploits;
    REPORT(logger, "Dumping an exploit to file " << ss.str());
    input->dumpExploit((char*) ss.str().c_str(), false);
    if (info_available)
    {
      if (!same_exploit)
      {
        stringstream ss(stringstream::in | stringstream::out);
        ss << config->getPrefix() << "stacktrace_" << report.size() - 1 << ".log";
        stack_trace->dumpFile((char*) ss.str().c_str());
        REPORT(logger, "Dumping stack trace to file " << ss.str());
      }
      else
      {
        stringstream ss(stringstream::in | stringstream::out);
        ss << config->getPrefix() << "stacktrace_" << exploitGroup << ".log";
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
    if (info_available)
    {
      if (!same_exploit)
      {
        stringstream ss(stringstream::in | stringstream::out);
        ss << config->getPrefix() << "stacktrace_" << report.size() - 1 << ".log";
        stack_trace->dumpFile((char*) ss.str().c_str());
        REPORT(logger, "Dumping stack trace to file " << ss.str());
      }
      else
      {
        stringstream ss(stringstream::in | stringstream::out);
        ss << config->getPrefix() << "stacktrace_" << exploitGroup << ".log";
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
      ss << config->getPrefix() << "exploit_" << exploits << "_" << i;
      REPORT(logger, "Dumping an exploit to file " << ss.str());
      input->files.at(i)->FileBuffer::dumpFile((char*) ss.str().c_str());
    }
  }
}

bool ExecutionManager::dumpMCExploit(Input* input, const char *exec_log)
{
  FileBuffer* mc_output = new FileBuffer(exec_log);
  char* error = strstr(mc_output->buf, "ERROR SUMMARY: ");
  long errors = -1;
  long definitely_lost = -1;
  long possibly_lost = -1;
  bool res = false;
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
  if ((errors > 0) || (((definitely_lost != -1) || (possibly_lost != -1)) && !killed))
  {
    time_t memchecktime;
    time(&memchecktime);
    string t = string(ctime(&memchecktime));
    REPORT(logger, "Error detected.");
    LOG(logger, "memcheck error time: " << t.substr(0, t.size() - 1));   
    if (config->usingSockets() || config->usingDatagrams())
    {
      stringstream ss(stringstream::in | stringstream::out);
      ss << config->getPrefix() << "memcheck_" << memchecks;
      REPORT(logger, "Dumping input for memcheck error to file " << ss.str());
      input->dumpExploit((char*) ss.str().c_str(), false);
    }
    else
    {
      for (int i = 0; i < input->files.size(); i++)
      {
        stringstream ss(stringstream::in | stringstream::out);
        ss << config->getPrefix() << "memcheck_" << memchecks << "_" << i;
        REPORT(logger, "Dumping input for memcheck error to file " << ss.str());
        input->files.at(i)->FileBuffer::dumpFile((char*) ss.str().c_str());
      }
    }
    res = true; 
  }
  delete mc_output;
  return res;
}

int ExecutionManager::checkAndScore(Input* input, bool addNoCoverage, const char* fileNameModifier, bool first_run)
{
  if (config->usingSockets() || config->usingDatagrams())
  {
    input->dumpExploit("replace_data", false, fileNameModifier);
  }
  else
  {
    input->dumpFiles(NULL, fileNameModifier);
  }
  vector<string> plugin_opts;
  ostringstream rp_data;
  rp_data << "--replace=replace_data" << fileNameModifier;
  if (config->usingSockets())
  {
    ostringstream cv_host;
    cv_host << "--host=" << config->getHost();
    plugin_opts.push_back(cv_host.str());

    ostringstream cv_port;
    cv_port << "--port=" << config->getPort();
    plugin_opts.push_back(cv_port.str());
    
    plugin_opts.push_back(rp_data.str().c_str());
    plugin_opts.push_back("--sockets=yes");

    LOG(logger, "setting alarm " << config->getAlarm());
    alarm(config->getAlarm());
    killed = false;
  }
  else if (config->usingDatagrams())
  { 
    plugin_opts.push_back(rp_data.str().c_str());
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

  string cv_exec_file = string("execution") + string(fileNameModifier) + string(".log");
  ostringstream cv_exec_log;
  cv_exec_log << "--log-file=" << cv_exec_file;
  plugin_opts.push_back(cv_exec_log.str());

  if (addNoCoverage)
  {
    plugin_opts.push_back("--no-coverage=yes");
  }
  if (strcmp(fileNameModifier, ""))
  {
    ostringstream cv_bb_log;
    cv_bb_log << "--filename=basic_blocks" << fileNameModifier << ".log";
    plugin_opts.push_back(cv_bb_log.str());
  }

  vector <string> new_prog_and_args = config->getProgAndArg();
  
  if (strcmp(fileNameModifier, "") && !(config->usingSockets()) && !(config->usingDatagrams()))
  {
    for (int i = 0; i < new_prog_and_args.size(); i ++)
    {
      for (int j = 0; j < input->files.size(); j ++)
      {
        if (!strcmp(new_prog_and_args[i].c_str(), input->files.at(j)->name))
        {
          new_prog_and_args[i].append(string(fileNameModifier));
          modified_input.insert(i);
        }
      }
    }
  }
  PluginExecutor plugin_exe(config->getDebug(), config->getTraceChildren(), config->getValgrind(), new_prog_and_args, plugin_opts, addNoCoverage ? COVGRIND : kind);
  curSockets = 0;
  bool enable_mutexes = (config->getSTPThreads() != 0) && !first_run;
  int thread_index = 0;
  if (strcmp(fileNameModifier, ""))
  {
    thread_index = atoi(string(fileNameModifier).substr(1).c_str());
  }
  time_t start_time = time(NULL);
  monitor->setState(CHECKER, start_time, thread_index);
  int exitCode = plugin_exe.run(thread_index);
  if (enable_mutexes) pthread_mutex_lock(&add_time_mutex);
  monitor->addTime(time(NULL), thread_index);
  if (enable_mutexes) pthread_mutex_unlock(&add_time_mutex);
  FileBuffer* mc_output;
  bool infoAvailable = false;
  bool sameExploit = false;
  int exploitGroup = 0;
  if (enable_mutexes) pthread_mutex_lock(&add_exploits_mutex);
  bool has_crashed = (exitCode == -1);
  if (!thread_num)
  {
    has_crashed = has_crashed && !killed;
  }
  else
  {
    has_crashed = has_crashed && !(((ParallelMonitor*) monitor)->getAlarmKilled(thread_index));
  }
  if (has_crashed)
  {
    FileBuffer* cv_output = new FileBuffer(cv_exec_file.c_str());
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
      report.push_back(ch);
    }
    dumpExploit(input, cv_output, infoAvailable, sameExploit, exploitGroup);
    exploits++;
    delete cv_output;
  }
  else if (config->usingMemcheck() && !addNoCoverage)
  {
    if (dumpMCExploit(input, cv_exec_file.c_str()))
    {
      memchecks ++;
    }
  }
  if (enable_mutexes) pthread_mutex_unlock(&add_exploits_mutex);
  if (!addNoCoverage)
  {
    int res = 0;
    string bb_name = string("basic_blocks") + string(fileNameModifier) + string(".log");
    int fd = open(bb_name.c_str(), O_RDWR);
    if (fd != -1)
    {
      struct stat fileInfo;
      fstat(fd, &fileInfo);
      int size = fileInfo.st_size / sizeof(long);
      if (size > 0)
      {
        unsigned long* basicBlockAddrs = new unsigned long[size];
        read(fd, basicBlockAddrs, fileInfo.st_size);
        close(fd);
        if (enable_mutexes) pthread_mutex_lock(&add_bb_mutex);
        for (int i = 0; i < size; i++)
        {
          if (basicBlocksCovered.find(basicBlockAddrs[i]) == basicBlocksCovered.end())
          {
            res++;
          }
          if(thread_num < 1)
          {
            basicBlocksCovered.insert(basicBlockAddrs[i]);
          }
          else
          {
            delta_bb_covered.insert(basicBlockAddrs[i]);
          }
        }
        if (enable_mutexes) pthread_mutex_unlock(&add_bb_mutex);
        delete[] basicBlockAddrs;
      }
    }
    return res;
  }
  else
  {
    return 0;
  }
}

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
    monitor->handleSIGALARM();
    killed = true;
    DBG(logger, "Time out. Valgrind is going to be killed");
  }
  signal(SIGALRM, alarmHandler);
}

void* exec_STP_CG(void* data)
{
  PoolThread* actor = (PoolThread*) data;
  ExecutionManager* this_pointer = (ExecutionManager*) (actor->getReadonlyDataUnit("this_pointer"));
  shared_data_unit inp = actor->getSharedDataUnit("inputs");
  multimap<Key, Input*, cmp>* inputs = (multimap <Key, Input*, cmp> *) (inp.data_unit);
  pthread_mutex_t* inputs_mutex = inp.mutex;
  Input* first_input = (Input*) (actor->getReadonlyDataUnit("first_input"));
  bool* actual = (bool*) (actor->getReadonlyDataUnit("actual"));
  long depth = (long) (actor->getPrivateDataUnit("depth"));
  long first_depth = (long) (actor->getPrivateDataUnit("first_depth"));
  int cur_tid = actor->getCustomTID();
  ostringstream cur_trace_log, input_modifier;
  input_modifier << "_" << actor->getCustomTID();
  cur_trace_log << "curtrace_" << actor->getCustomTID() << ".log";
  STP_Input si;
  si.setFile(cur_trace_log.str().c_str());
  STP_Executor stp_exe(this_pointer->getConfig()->getDebug(), this_pointer->getConfig()->getValgrind());        
  nokill = true;
  time_t start_time = time(NULL);
  monitor->setState(STP, start_time, cur_tid);
  STP_Output *out = stp_exe.run(&si, cur_tid);
  pthread_mutex_lock(&add_time_mutex);
  monitor->addTime(time(NULL), cur_tid);
  pthread_mutex_unlock(&add_time_mutex);
  nokill = false;
  if (out == NULL)
  {
    if (!monitor->getKilledStatus())
    {
      ERR(logger, "STP has encountered an error");
      FileBuffer f(cur_trace_log.str().c_str());
      ERR(logger, cur_trace_log.str().c_str() << ":\n" << string(f.buf));
    }
  }
  else if (out->getFile() != NULL)
  {
    FileBuffer f(out->getFile());
    DBG(logger, "Thread #" << cur_tid << ": stp output:\n" << string(f.buf));
    Input* next = new Input();
    int st_depth = first_input->startdepth;
    for (int k = 0; k < first_input->files.size(); k++)
    { 
      FileBuffer* fb = first_input->files.at(k);
      fb = fb->forkInput(out->getFile());
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
      next->startdepth = st_depth + depth + 1;
      bool* prediction = new bool[st_depth + depth];
      for (int j = 0; j < st_depth + depth - 1; j++)
      {
        prediction[j] = actual[j];
      }
      prediction[st_depth + depth - 1] = !actual[st_depth + depth - 1];
      next->prediction = prediction;
      next->predictionSize = st_depth + depth;
      next->parent = first_input;
      int score = this_pointer->checkAndScore(next, trace_kind, input_modifier.str().c_str());
      if (!trace_kind)
      {
        LOG(logger, "Thread #" << cur_tid << ": score=" << score << "\n");
        pthread_mutex_lock(inputs_mutex);
        inputs->insert(make_pair(Key(score, first_depth + depth + 1), next));
        pthread_mutex_unlock(inputs_mutex);
      }
    }
  }
  if (out != NULL) delete out;
}

int ExecutionManager::runSTPAndCGParallel(bool _trace_kind, multimap<Key, Input*, cmp> * inputs, Input * first_input, unsigned long first_depth)
{
  int actualfd = open("actual.log", O_RDWR);
  bool* actual = new bool[first_input->startdepth - 1 + config->getDepth()];
  read(actualfd, actual, (first_input->startdepth - 1 + config->getDepth()) * sizeof(bool));
  close(actualfd);
  int active_threads = thread_num;
  long depth = 0;
  int thread_status[thread_num];
  pthread_mutex_init(&add_inputs_mutex, NULL);
  pthread_mutex_init(&add_exploits_mutex, NULL);
  pthread_mutex_init(&add_bb_mutex, NULL);
  pthread_mutex_init(&add_time_mutex, NULL);
  pthread_cond_init(&finish_cond, NULL);
  FileBuffer *trace = new FileBuffer((!trace_kind) ? "trace.log" : "dangertrace.log");
  trace_kind = _trace_kind;
  for (int j = 0; j < thread_num; j ++)
  {
    threads[j].setCustomTID(j + 1);
    threads[j].setPoolSync(&finish_mutex, &finish_cond, &(thread_status[j]), &active_threads);
    threads[j].addSharedDataUnit((void*) inputs, string("inputs"),  &add_inputs_mutex);
    threads[j].addSharedDataUnit((void*) first_input, string("first_input"));
    threads[j].addSharedDataUnit((void*) actual, string("actual"));
    threads[j].addSharedDataUnit((void*) this, string("this_pointer"));
    thread_status[j] = -1;
  }
  char* query = trace->buf;
  while((query = strstr(query, "QUERY(FALSE);")) != NULL)
  {
    depth ++;
    query ++;
  }
  STP_Output* outputs[depth];
  int thread_counter;
  pool_data* external_data = new pool_data[depth];
  for (int i = 0; i < depth; i ++)
  {
    pthread_mutex_lock(&finish_mutex);
    if (active_threads == 0) 
    {
      pthread_cond_wait(&finish_cond, &finish_mutex);
    }
    for (thread_counter = 0; (thread_counter < thread_num) && (thread_status[thread_counter] == 0); thread_counter ++) {}
    if (thread_status[thread_counter] == 1)
    {
      threads[thread_counter].waitForThread();
    }
    active_threads --;
    thread_status[thread_counter] = 0;
    threads[thread_counter].clearPrivateData();
    threads[thread_counter].addPrivateDataUnit((void*) i, string("depth"));
    threads[thread_counter].addPrivateDataUnit((void*) first_depth, string("first_depth"));
    external_data[i].work_func = exec_STP_CG;
    external_data[i].data = &(threads[thread_counter]);
    ostringstream cur_trace;
    cur_trace << "curtrace_" << thread_counter + 1 << ".log";
    trace->invertQueryAndDump(cur_trace.str().c_str());
    in_thread_creation = thread_counter;
    threads[thread_counter].createThread(&(external_data[i]));
    in_thread_creation = -1;
    pthread_mutex_unlock(&finish_mutex);
  }
  bool do_wait = false;
  if (depth)
  {
    for (int i = 0; i < thread_num; i ++)
    {
      pthread_mutex_lock(&finish_mutex);
      do_wait = (thread_status[i] == 0);
      pthread_mutex_unlock(&finish_mutex);
      if (do_wait)
      {
        threads[i].waitForThread();
      }
    }
  }
  delete trace;
  pthread_mutex_destroy(&add_inputs_mutex);
  pthread_mutex_destroy(&add_exploits_mutex);
  pthread_mutex_destroy(&add_bb_mutex);
  pthread_mutex_destroy(&add_time_mutex);
  pthread_cond_destroy(&finish_cond);
  delete []external_data;
  delete []actual;
  return depth;
}

void dummy_handler(int signo)
{

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
      if (config->getAgent())
      {
        updateInput(initial);
      }
      signal(SIGALRM, alarmHandler);
    }
    initial->startdepth = config->getStartdepth();
    int score;
    score = checkAndScore(initial, false, "", true);
    basicBlocksCovered.insert(delta_bb_covered.begin(), delta_bb_covered.end());
    LOG(logger, "score=" << score);
    inputs.insert(make_pair(Key(score, 0), initial));
    bool delete_fi;
    
    while (!inputs.empty()) 
    {
      delete_fi = false;
      REPORT(logger, "Starting iteration " << runs);
      LOG(logger, "inputs.size()=" << inputs.size());
      delta_bb_covered.clear();
      multimap<Key, Input*, cmp>::iterator it = --inputs.end();
      Input* fi = it->second;
      unsigned int scr = it->first.score;
      unsigned int dpth = it->first.depth;
      LOG(logger, "selected next input with score " << scr);

      if (config->usingSockets() || config->usingDatagrams())
      {
        fi->dumpExploit("replace_data", true);
      }
      else
      {
        fi->dumpFiles();
      }
      ostringstream tg_depth;
      vector<string> plugin_opts;
      bool newInput = false;
      if ((scr == 0) && config->getAgent())
      {
        LOG(logger, "All inputs have zero score: requesting new input");
        signal(SIGUSR2, dummy_handler);
        kill(getppid(), SIGUSR1);
        pause();
        int descr = open("startdepth.log", O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
        int startdepth;
        read(descr, &startdepth, sizeof(int));
        close(descr);
        if (startdepth > 0)
        {
          tg_depth << "--startdepth=" << startdepth;
          newInput = true;
        }
        else
        {
          config->setNotAgent();
          delete_fi = true;
          inputs.erase(it);
          if (runs > 0)
          {
            plugin_opts.push_back("--check-prediction=yes");
          }
          tg_depth << "--startdepth=" << fi->startdepth;
        }
      }
      else
      {
        delete_fi = true;
        inputs.erase(it);
        if (runs > 0)
        {
          plugin_opts.push_back("--check-prediction=yes");
        }
        tg_depth << "--startdepth=" << fi->startdepth;
      }
      ostringstream tg_invert_depth;
      tg_invert_depth << "--invertdepth=" << config->getDepth();
   
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
      
      PluginExecutor plugin_exe(config->getDebug(), config->getTraceChildren(), config->getValgrind(), config->getProgAndArg(), plugin_opts, TRACEGRIND);
      if (config->getTracegrindAlarm() == 0)
      {
        nokill = true;
      }
      time_t start_time = time(NULL);
      monitor->setState(TRACER, start_time);
      int exitCode = plugin_exe.run();
      monitor->addTime(time(NULL));
      if (config->getTracegrindAlarm() == 0)
      {      
        nokill = false;
      }
      if (config->usingSockets() || config->usingDatagrams())
      {
        updateInput(fi);
      }

      if (exitCode == -1)
      {
        LOG(logger, "failure in tracegrind\n");
      }

      int divfd = open("divergence.log", O_RDWR);
      if ((divfd != -1) && config->getDebug() && (runs > 0) && !newInput)
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
            ss << config->getPrefix() << "divergence_" << divergences;
            LOG(logger, "dumping divergent input to file " << ss.str());
            fi->parent->dumpExploit((char*) ss.str().c_str(), false);
          }
          else
          {
            for (int i = 0; i < fi->parent->files.size(); i++)
            {
              stringstream ss(stringstream::in | stringstream::out);
              ss << config->getPrefix() << "divergence_" << divergences << "_" << i;
              LOG(logger, "dumping divergent input to file " << ss.str());
              fi->parent->files.at(i)->FileBuffer::dumpFile((char*) ss.str().c_str());
            }
          }
          divergences++;
          DBG(logger, "with startdepth=" << fi->parent->startdepth << " and invertdepth=" << config->getDepth() << "\n");
          close(divfd);
          if (scr == 0) 
          {
            runs++;
            if (is_distributed)
            {
              talkToServer(inputs);
            }
            continue;
          }
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
      int depth = 0;
      if (thread_num)
      {
        if (config->getCheckDanger())
        {
          depth = runSTPAndCGParallel(true, &inputs, fi, dpth);
        }
        depth = runSTPAndCGParallel(false, &inputs, fi, dpth);
      }
      else
      {
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
            dtrace.invertQueryAndDump("curdtrace.log");
            STP_Input si;
            //si.setFile(".avalanche/curdtrace.log");
            si.setFile("curdtrace.log");
            //the rest stuff
            STP_Executor stp_exe(config->getDebug(), config->getValgrind());        
            nokill = true;
            time_t start_time = time(NULL);
            monitor->setState(STP, start_time);
            STP_Output *stp_output = stp_exe.run(&si);
            monitor->addTime(time(NULL));
            nokill = false;
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
                checkAndScore(next, true);
                delete next;
              }
            }
            delete stp_output;
          }
        }
        FileBuffer trace("trace.log");
        char* query;
        while ((query = strstr(trace.buf, "QUERY(FALSE)")) != NULL)
        {
          depth++;
          trace.invertQueryAndDump("curtrace.log");
          STP_Input si;
          //si.setFile(".avalanche/curtrace.log");
          si.setFile("curtrace.log");
          //the rest stuff
          STP_Executor stp_exe(config->getDebug(), config->getValgrind());        
          nokill = true;
          time_t start_time = time(NULL);
          monitor->setState(STP, start_time);
          STP_Output *stp_output = stp_exe.run(&si);
          monitor->addTime(time(NULL));
          nokill = false;
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
              score = checkAndScore(next, false);
              LOG(logger, "score=" << score << "\n");
              inputs.insert(make_pair(Key(score, dpth + depth), next));
            }
          }
          delete stp_output;
        }
        delete []actual;
      }
      if (depth == 0)
      {
        LOG(logger, "no QUERY's found");
      }
      runs++;
      if (delete_fi)
      {
        if (initial != fi)
        {
          delete fi;
        }
      }
      basicBlocksCovered.insert(delta_bb_covered.begin(), delta_bb_covered.end());
      if (is_distributed)
      {
        talkToServer(inputs);
      }
    }
    if (!(config->usingSockets()) && !(config->usingDatagrams()))
    {
      initial->dumpFiles();
    }
}

#define WRITE(var, size) \
    do {\
      if (write(distfd, var, size) == -1) {\
        NET(logger, "Connection with server lost"); \
        NET(logger, "Continuing work in local mode"); \
        is_distributed = false; \
        return; } \
    } while(0)

void ExecutionManager::talkToServer(multimap<Key, Input*, cmp>& inputs)
{
  NET(logger, "Communicating with server");
  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(distfd, &readfds);
  struct timeval timer;
  timer.tv_sec = 0;
  timer.tv_usec = 0;
  select(distfd + 1, &readfds, NULL, NULL, &timer);
  while (FD_ISSET(distfd, &readfds)) 
  {
    char c = '\0';
    if (read(distfd, &c, 1) < 1)
    {
      NET(logger, "Connection with server lost");
      is_distributed = false;
      NET(logger, "Continuing work in local mode");
      return;
    }
    if (c == 'a')
    {
      NET(logger, "Sending options and data");
      write(distfd, "r", 1); 
      //sending "r"(responding) before data - this is to have something different from "q", so that server
      //can understand that main avalanche finished normally
      int size;
      read(distfd, &size, sizeof(int));
      while (size > 0)
      {
        if (inputs.size() <= 1)
        {
          break;
        }
        multimap<Key, Input*, cmp>::iterator it = --inputs.end();
        it--;
        Input* fi = it->second;
        int filenum = fi->files.size();
        WRITE(&filenum, sizeof(int));
        bool sockets = config->usingSockets();
        WRITE(&sockets, sizeof(bool));
        bool datagrams = config->usingDatagrams();
        WRITE(&datagrams, sizeof(bool));
        for (int j = 0; j < fi->files.size(); j ++)
        {
          FileBuffer* fb = fi->files.at(j);
          if (!config->usingDatagrams() && ! config->usingSockets())
          {
            int namelength = config->getFile(j).length();
            WRITE(&namelength, sizeof(int));
            WRITE(config->getFile(j).c_str(), namelength);
          }
          WRITE(&(fb->size), sizeof(int));
          WRITE(fb->buf, fb->size);
          /*printf("fb->size=%d\n", fb->size);
          for (int j = 0; j < fb->size; j++)
          {
            printf("%x", fb->buf[j]);
          }*/
        }
        //printf("\n");
        WRITE(&fi->startdepth, sizeof(int));
        int depth = config->getDepth();
        WRITE(&depth, sizeof(int));
        unsigned int alarm = config->getAlarm();
        WRITE(&alarm, sizeof(int));
        unsigned int tracegrindAlarm = config->getTracegrindAlarm();
        WRITE(&tracegrindAlarm, sizeof(int));
        int threads = config->getSTPThreads();
        WRITE(&threads, sizeof(int));

        int progArgsNum = config->getProgAndArg().size();
        WRITE(&progArgsNum, sizeof(int));
        //printf("argsnum=%d\n", progArgsNum);

        bool useMemcheck = config->usingMemcheck();
        WRITE(&useMemcheck, sizeof(bool));
        bool leaks = config->checkForLeaks();
        WRITE(&leaks, sizeof(bool));
        bool traceChildren = config->getTraceChildren();
        WRITE(&traceChildren, sizeof(bool));
        bool checkDanger = config->getCheckDanger();
        WRITE(&checkDanger, sizeof(bool));
        bool debug = config->getDebug();
        WRITE(&debug, sizeof(bool));
        bool verbose = config->getVerbose();
        WRITE(&verbose, sizeof(bool));
        bool suppressSubcalls = config->getSuppressSubcalls();
        WRITE(&suppressSubcalls, sizeof(bool));
        bool STPThreadsAuto = config->getSTPThreadsAuto();
        WRITE(&STPThreadsAuto, sizeof(bool));

        if (sockets)
        {
          string host = config->getHost();
          int length = host.length();
          WRITE(&length, sizeof(int));
          WRITE(host.c_str(), length);
          unsigned int port = config->getPort();
          WRITE(&port, sizeof(int));
        }

        if (config->getInputFilterFile() != "")
        {
          FileBuffer mask(config->getInputFilterFile().c_str());
          WRITE(&mask.size, sizeof(int));
          WRITE(mask.buf, mask.size);
        }
        else
        {
          int z = 0;
          WRITE(&z, sizeof(int));
        }

        int funcFilters = config->getFuncFilterUnitsNum();
        WRITE(&funcFilters, sizeof(int));
        for (int i = 0; i < config->getFuncFilterUnitsNum(); i++)
        {
          string f = config->getFuncFilterUnit(i);
          int length = f.length();
          WRITE(&length, sizeof(int));
          WRITE(f.c_str(), length);
        }
        if (config->getFuncFilterFile() != "")
        {
          FileBuffer filter(config->getFuncFilterFile().c_str());
          WRITE(&filter.size, sizeof(int));
          WRITE(filter.buf, filter.size);
        }
        else
        {
          int z = 0;
          WRITE(&z, sizeof(int));
        }

        for (vector<string>::const_iterator it = config->getProgAndArg().begin(); it != config->getProgAndArg().end(); it++)
        {
          int argsSize = it->length();
          WRITE(&argsSize, sizeof(int));
          WRITE(it->c_str(), argsSize);
        }
        if (it->second != initial)
        {
          delete it->second;
        }
        inputs.erase(it);
        size--;
      }
      while (size > 0)
      {
        int tosend = 0;
        WRITE(&tosend, sizeof(int));
        size--;
      }
    }
    else if (c == 'g')
    {
      //printf("received get\n");
      write(distfd, "r", 1);
      //sending "r"(responding) before data - this is to have something different from "q", so that server
      //can understand that main avalanche finished normally
      int size;
      read(distfd, &size, sizeof(int));
      while (size > 0)
      {
        if (inputs.size() <= 1)
        { 
          break;
        }
        NET(logger, "Sending input");
        multimap<Key, Input*, cmp>::iterator it = --inputs.end();
        it--;
        Input* fi = it->second;
        for (int j = 0; j < fi->files.size(); j ++)
        {
          FileBuffer* fb = fi->files.at(j);
          WRITE(&(fb->size), sizeof(int));
          WRITE(fb->buf, fb->size);
        }
        WRITE(&fi->startdepth, sizeof(int));
        if (it->second != initial)
        {
          delete it->second;
        }
        inputs.erase(it);
        size--;
      }
      while (size > 0)
      {
        int tosend = 0;
        write(distfd, &tosend, sizeof(int));
        size--;
      }
    }
    else
    {
      int tosend = 0;
      WRITE(&tosend, sizeof(int));
    }
    FD_ZERO(&readfds);
    FD_SET(distfd, &readfds);
    select(distfd + 1, &readfds, NULL, NULL, &timer);      
  }
}

ExecutionManager::~ExecutionManager()
{
    DBG(logger, "Destructing plugin manager");

    if (is_distributed)
    {
      write(distfd, "q", 1);
      shutdown(distfd, SHUT_RDWR);
      close(distfd);
    }

    delete config;
}

