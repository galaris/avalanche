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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <string>
#include <vector>
#include <set>

using namespace std;

time_t tg_time = 0;
bool intg = false;
time_t tg_start;
time_t tg_end;
time_t *cv_time;
bool *incv;
time_t *cv_start;
time_t *cv_end;
time_t *stp_time;
bool *instp;
time_t *stp_start;
time_t *stp_end;

PoolThread *threads;
extern int thread_num;

extern pid_t child_pid;
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
  
vector<Chunk*> report;

set <int> modified_input;

pthread_mutex_t add_inputs_mutex;
pthread_mutex_t add_exploits_mutex;
pthread_mutex_t add_bb_mutex;
pthread_mutex_t add_cv_time_mutex;

ExecutionManager::ExecutionManager(OptionConfig *opt_config)
{
    DBG(logger, "Initializing plugin manager");

    cond_depth  = 1;
    config      = new OptionConfig(opt_config);
    exploits    = 0;
    divergences = 0;
    if (opt_config->getDistributed())
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

      printf("connected\n");
      write(distfd, "m", 1);
   }
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
  if (strcmp(fileNameModifier, "") && kind == COVGRIND)
  {
    ostringstream cv_bb_log;
    cv_bb_log << "--filename=basic_blocks" << fileNameModifier << ".log";
    plugin_opts.push_back(cv_bb_log.str());
  }

  vector <string> new_prog_and_args = config->getProgAndArg();
  
  if (strcmp(fileNameModifier, ""))
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
  bool enableMutexes = (config->getSTPThreads() != 0) && !first_run;
  int thread_index = 0;
  if (strcmp(fileNameModifier, ""))
  {
    thread_index = atoi(string(fileNameModifier).substr(1).c_str());
  }
  cv_start[thread_index] = time(NULL);
  incv[thread_index] = true;
  int exitCode = plugin_exe.run(thread_index);
  incv[thread_index] = false;
  cv_end[thread_index] = time(NULL);
  cv_time[thread_index] += cv_end[thread_index] - cv_start[thread_index];
  FileBuffer* mc_output;
  bool infoAvailable = false;
  bool sameExploit = false;
  int exploitGroup = 0;
  
  if (enableMutexes) pthread_mutex_lock(&add_exploits_mutex);
  if ((exitCode == -1) && !killed)
  {
    FileBuffer* cv_output = new FileBuffer(cv_exec_file.c_str());
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
      ss << config->getPrefix() << "exploit_" << exploits;
      REPORT(logger, "Dumping an exploit to file " << ss.str());
      input->dumpExploit((char*) ss.str().c_str(), false);
      if (infoAvailable)
      {
        if (!sameExploit)
        {
          stringstream ss(stringstream::in | stringstream::out);
          ss << config->getPrefix() << "stacktrace_" << report.size() - 1 << ".log";
          cv_output->dumpFile((char*) ss.str().c_str());
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
      if (infoAvailable)
      {
        if (!sameExploit)
        {
          stringstream ss(stringstream::in | stringstream::out);
          ss << config->getPrefix() << "stacktrace_" << report.size() - 1 << ".log";
          cv_output->dumpFile((char*) ss.str().c_str());
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
    exploits++;
    if (deleteBuffer)
    {
      delete cv_output;
    }
  }
  else if (config->usingMemcheck() && !addNoCoverage)
  {
    FileBuffer* mc_output = new FileBuffer(cv_exec_log.str().c_str());
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
      memchecks++;  
    }
    delete mc_output;
  }
  if (enableMutexes) pthread_mutex_unlock(&add_exploits_mutex);
  if (!addNoCoverage)
  {
    int res = 0;
    string bb_name = string("basic_blocks") + string(fileNameModifier) + string(".log");
    int fd = open(bb_name.c_str(), O_RDWR);
    struct stat fileInfo;
    fstat(fd, &fileInfo);
    int size = fileInfo.st_size / sizeof(long);
    unsigned long* basicBlockAddrs = new unsigned long[size];
    read(fd, basicBlockAddrs, fileInfo.st_size);
    close(fd);
    if (enableMutexes) pthread_mutex_lock(&add_bb_mutex);
    for (int i = 0; i < size; i++)
    {
      if (basicBlocksCovered.insert(basicBlockAddrs[i]).second)
      {
        res++;
      }
    }
    if (enableMutexes) pthread_mutex_unlock(&add_bb_mutex);
    delete[] basicBlockAddrs;
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
    kill(child_pid, SIGALRM);
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
  inp = actor->getSharedDataUnit("trace");
  FileBuffer * fbuf = (FileBuffer*) (inp.data_unit);
  pthread_mutex_t* trace_mutex = inp.mutex;
  bool* actual = (bool*) (actor->getReadonlyDataUnit("actual"));
  int depth = (int) (actor->getPrivateDataUnit("depth"));
  int first_depth = (int) (actor->getPrivateDataUnit("first_depth"));
  int cur_tid = actor->getCustomTID();
  ostringstream cur_trace_log, input_modifier;
  cur_trace_log << "curtrace_" << cur_tid << ".log";
  input_modifier << "_" << cur_tid;
  pthread_mutex_lock(trace_mutex);
  char* query = strstr(fbuf->buf, "QUERY(FALSE);");
  if (query[-4] == '0')
  {
    query[-4] = '1';
  } 
  else if (query[-4] == '1')
  {
    query[-4] = '0';
  }
  unsigned int oldsize = fbuf->size;
  fbuf->size = (query - fbuf->buf) + 13;
  fbuf->dumpFile(cur_trace_log.str().c_str());
  for (int k = 0; k < 13; k++)
  {
    query[k] = '\n';
  }
  if (query[-4] == '0')
  {
    query[-4] = '1';
  } 
  else if (query[-4] == '1')
  {
    query[-4] = '0';
  }
  fbuf->size = oldsize;
  pthread_mutex_unlock(trace_mutex);
  STP_Input si;
  si.setFile(cur_trace_log.str().c_str());
  STP_Executor stp_exe(this_pointer->getConfig()->getDebug(), this_pointer->getConfig()->getValgrind());        
  stp_start[cur_tid] = time(NULL);
  instp[cur_tid] = true;
  nokill = true;
  STP_Output *out = stp_exe.run(&si, cur_tid);
  nokill = false;
  instp[cur_tid] = false;
  stp_end[cur_tid] = time(NULL);
  stp_time[cur_tid] += stp_end[cur_tid] - stp_start[cur_tid];
  if (out == NULL)
  {
    ERR(logger, "STP has encountered an error");
    FileBuffer f(cur_trace_log.str().c_str());
    ERR(logger, cur_trace_log.str().c_str() << ":\n" << string(f.buf));
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

void ExecutionManager::runSTPAndCGParallel(bool _trace_kind, multimap<Key, Input*, cmp> * inputs, Input * first_input, unsigned int first_depth)
{
  int actualfd = open("actual.log", O_RDWR);
  bool* actual = new bool[first_input->startdepth - 1 + config->getDepth()];
  read(actualfd, actual, (first_input->startdepth - 1 + config->getDepth()) * sizeof(bool));
  close(actualfd);
  threads = new PoolThread[thread_num];
  pthread_mutex_t finish_mutex;
  pthread_cond_t finish_cond;
  pthread_mutex_t cutSTP_mutex;
  int active_threads = thread_num;
  int depth = 0;
  int thread_status[thread_num];
  pthread_mutex_init(&add_inputs_mutex, NULL);
  pthread_mutex_init(&add_exploits_mutex, NULL);
  pthread_mutex_init(&add_bb_mutex, NULL);
  pthread_mutex_init(&finish_mutex, NULL);
  pthread_cond_init(&finish_cond, NULL);
  pthread_mutex_init(&cutSTP_mutex, NULL);
  FileBuffer trace((!trace_kind) ? "trace.log" : "dangertrace.log");
  trace_kind = _trace_kind;
  for (int j = 0; j < thread_num; j ++)
  {
    threads[j].setCustomTID(j);
    threads[j].setPoolSync(&finish_mutex, &finish_cond, &(thread_status[j]), &active_threads);
    threads[j].addSharedDataUnit((void*) inputs, string("inputs"),  &add_inputs_mutex);
    threads[j].addSharedDataUnit((void*) first_input, string("first_input"));
    threads[j].addSharedDataUnit((void*) actual, string("actual"));
    threads[j].addSharedDataUnit((void*) this, string("this_pointer"));
    threads[j].addSharedDataUnit((void*) &trace, string("trace"), &cutSTP_mutex);
    thread_status[j] = -1;
  }
  char* query = trace.buf;
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
    threads[thread_counter].createThread(&(external_data[i]));
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
  pthread_mutex_destroy(&add_inputs_mutex);
  pthread_mutex_destroy(&add_exploits_mutex);
  pthread_mutex_destroy(&add_bb_mutex);
  pthread_mutex_destroy(&cutSTP_mutex);
  pthread_mutex_destroy(&finish_mutex);
  pthread_cond_destroy(&finish_cond);
  delete []external_data;
  delete []threads;
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
    initial->startdepth = config->getStartdepth();
    int score;
    score = checkAndScore(initial, false, "", true);
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
            if (config->getDistributed())
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
          runSTPAndCGParallel(true, &inputs, fi, dpth);
        }
        runSTPAndCGParallel(false, &inputs, fi, dpth);
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
            *stp_start = time(NULL);
            *instp = true;
            nokill = true;
            STP_Output *stp_output = stp_exe.run(&si);
            nokill = false;
            *instp = false;
            *stp_end = time(NULL);
            *stp_time += *(stp_end) - *(stp_start);
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
          *stp_start = time(NULL);
          *instp = true;
          nokill = true;
          STP_Output *stp_output = stp_exe.run(&si);
          nokill = false;
          *instp = false;
          *stp_end = time(NULL);
          *stp_time += *(stp_end) - *(stp_start);
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
      }
      if (depth == 0)
      {
        LOG(logger, "no QUERY's found");
      }
      runs++;

      if (config->getDistributed())
      {
        talkToServer(inputs);
      }
    }
    initial->dumpFiles();
}

void ExecutionManager::talkToServer(multimap<Key, Input*, cmp>& inputs)
{
  printf("talking to server\n");
  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(distfd, &readfds);
  struct timeval timer;
  timer.tv_sec = 0;
  timer.tv_usec = 0;
  select(distfd + 1, &readfds, NULL, NULL, &timer);
  while (FD_ISSET(distfd, &readfds)) 
  {
    printf("here 861\n");
    char c;
    read(distfd, &c, 1);
    if ((c == 'a') && (inputs.size() > 1))
    {
      printf("received all\n");
      multimap<Key, Input*, cmp>::iterator it = --inputs.end();
      it--;
      Input* fi = it->second;
      FileBuffer* fb = fi->files.at(0);
      int namelength = config->getFile(0).length();
      write(distfd, &namelength, sizeof(int));
      write(distfd, config->getFile(0).c_str(), namelength);
      write(distfd, &(fb->size), sizeof(int));
      write(distfd, fb->buf, fb->size);
      printf("fb->size=%d\n", fb->size);
      for (int j = 0; j < fb->size; j++)
      {
        printf("%x", fb->buf[j]);
      }
      printf("\n");
      write(distfd, &fi->startdepth, sizeof(int));
      int depth = config->getDepth();
      write(distfd, &depth, sizeof(int));
      unsigned int alarm = config->getAlarm();
      write(distfd, &alarm, sizeof(int));
      int progArgsNum = config->getProgAndArg().size();
      write(distfd, &progArgsNum, sizeof(int));
      printf("argsnum=%d\n", progArgsNum);

      bool useMemcheck = config->usingMemcheck();
      write(distfd, &useMemcheck, sizeof(bool));
      bool leaks = config->checkForLeaks();
      write(distfd, &leaks, sizeof(bool));
      bool traceChildren = config->getTraceChildren();
      write(distfd, &traceChildren, sizeof(bool));
      bool checkDanger = config->getCheckDanger();
      write(distfd, &checkDanger, sizeof(bool));
      for (vector<string>::const_iterator it = config->getProgAndArg().begin(); it != config->getProgAndArg().end(); it++)
      {
        int argsSize = it->length();
        write(distfd, &argsSize, sizeof(int));
        write(distfd, it->c_str(), argsSize);
      }
      inputs.erase(it);
    }
    else if ((c == 'g') && (inputs.size() > 1))
    {
      printf("received get\n");
      multimap<Key, Input*, cmp>::iterator it = --inputs.end();
      it--;
      Input* fi = it->second;
      FileBuffer* fb = fi->files.at(0);
      write(distfd, &(fb->size), sizeof(int));
      write(distfd, fb->buf, fb->size);
      write(distfd, &fi->startdepth, sizeof(int));
      inputs.erase(it);
    }
    else
    {
      int tosend = 0;
      write(distfd, &tosend, sizeof(int));
    }
    FD_ZERO(&readfds);
    FD_SET(distfd, &readfds);
    select(distfd + 1, &readfds, NULL, NULL, &timer);      
  }
}

ExecutionManager::~ExecutionManager()
{
    DBG(logger, "Destructing plugin manager");

    delete config;
}

