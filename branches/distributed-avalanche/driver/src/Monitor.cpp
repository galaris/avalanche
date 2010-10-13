/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*------------------------------------ Monitor.cpp ---------------------------------------*/
/*----------------------------------------------------------------------------------------*/

/*
   Copyright (C) 2010 Michael Ermakov
      mermakov@ispras.ru

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

#include "Monitor.h"
#include <sstream>
#include <signal.h>
#include <algorithm>
#include <iterator>

Monitor::Monitor(std::string checker_name) : is_killed(false)
{
  module_name[CHECKER] = checker_name;
  module_name[TRACER] = "tracegrind";
  module_name[STP] = "stp";
}

SimpleMonitor::SimpleMonitor(std::string checker_name) : Monitor(checker_name), 
                                                         current_state(OUT)
{
  for (int i = 0; i < MODULE_COUNT; i ++)
  {
    module_time[i] = 0;
  }
}
            
void SimpleMonitor::addTime(time_t end_time, unsigned int thread_index)
{
  if (current_state != OUT)
  {
    module_time[current_state] += end_time - start_time;
    current_state = OUT;
  }
}
            
std::string SimpleMonitor::getStats(time_t global_time)
{
  std::ostringstream result;
  for (int i = 0; i < MODULE_COUNT; i ++)
  {
    result << module_name[i] << ": " << module_time[i];
    if (global_time != 0)
    {
      result << " (" << 100 * ((double) module_time[i]) / global_time << "%)";
    }
    result << ((i < MODULE_COUNT - 1) ? ", " : "");
  }
  return result.str();
}

void SimpleMonitor::handleSIGKILL()
{
  if (current_state != OUT)
  {
    kill(current_pid, SIGKILL);
    addTime(start_time, time(NULL));
  }
}

ParallelMonitor::ParallelMonitor(std::string checker_name, unsigned int _thread_num, time_t _time_shift) : Monitor(checker_name),
                                                                                                          time_shift(_time_shift)
{
  thread_num = _thread_num;
  current_state = new state[thread_num + 1];
  checker_start_time = new time_t[thread_num];
  stp_start_time = new time_t[thread_num];
  current_pid = new pid_t[thread_num + 1];
  for (int i = 0; i < thread_num; i ++)
  {
    current_state[i] = OUT;
    checker_start_time[i] = stp_start_time[i] = 0;
  }
}

ParallelMonitor::~ParallelMonitor()
{
  delete []current_state;
  delete []checker_start_time;
  delete []stp_start_time;
  delete []current_pid;
}

void ParallelMonitor::setState(state _state, time_t _start_time, unsigned int thread_index)
{
  current_state[thread_index] = _state;
  if (_state == STP)
  {
    stp_start_time[thread_index] = _start_time;
  }
  else if (_state == CHECKER)
  {
    checker_start_time[thread_index] = _start_time;
  }
  else if (_state == TRACER)
  {
    tracer_start_time = _start_time;
  }
}

void ParallelMonitor::addTime(time_t end_time, unsigned int thread_index)
{
  if (current_state[thread_index] == TRACER)
  {
    tracer_time += end_time - tracer_start_time;
    current_state[thread_index] = OUT;
  }
  else if (current_state[thread_index] != OUT)
  {
    time_t st_time = (current_state[thread_index] == CHECKER) ? checker_start_time[thread_index] : stp_start_time[thread_index];
    if (end_time > st_time)
    {
      interval new_interval;
      new_interval.first = st_time - time_shift;
      new_interval.second = end_time - time_shift;
      if (current_state[thread_index] == CHECKER)
      {
        checker_time.insert(new_interval);
      }
      else
      {
        stp_time.insert(new_interval);
      }
      current_state[thread_index] = OUT;
    }
  }
}

static std::set <time_t> getRealTimeSet(const std::set <interval> &time_set)
{
  std::set <time_t> unique_set;
  for (std::set <interval>::iterator i = time_set.begin(); i != time_set.end(); i ++)
  {
    for (time_t j = (*i).first; j != (*i).second; j ++)
    {
      unique_set.insert(j);
    }
  }
  return unique_set;
}

std::string ParallelMonitor::getStats(time_t global_time)
{
  std::ostringstream result;
  std::set <time_t> tmp_set, real_stp_set, real_checker_set;
#define EXTENDED_MODULE_COUNT 4
  time_t module_time[EXTENDED_MODULE_COUNT];
  real_checker_set = getRealTimeSet(checker_time);
  real_stp_set = getRealTimeSet(stp_time);
  module_time[TRACER_OUTPUT] = tracer_time;
  std::set_difference(real_checker_set.begin(), real_checker_set.end(), real_stp_set.begin(), real_stp_set.end(), std::inserter(tmp_set, tmp_set.begin()));
  module_time[CHECKER_OUTPUT] = tmp_set.size();
  tmp_set.clear();
  std::set_difference(real_stp_set.begin(), real_stp_set.end(), real_checker_set.begin(), real_checker_set.end(), std::inserter(tmp_set, tmp_set.begin()));
  module_time[STP_OUTPUT] = tmp_set.size();
  tmp_set.clear();
  std::set_intersection(real_stp_set.begin(), real_stp_set.end(), real_checker_set.begin(), real_checker_set.end(), std::inserter(tmp_set, tmp_set.begin()));
  module_time[CHECKER_AND_STP_OUTPUT] = tmp_set.size();
  std::string extended_module_name[EXTENDED_MODULE_COUNT];
  for (int i = 0; i < MODULE_COUNT; i ++)
  {
    extended_module_name[i] = (i == 0) ? module_name[i] : (module_name[i] + std::string(" only"));
  }
  extended_module_name[CHECKER_AND_STP_OUTPUT] = module_name[CHECKER] + std::string(" & ") + module_name[STP];
  for (int i = 0; i < EXTENDED_MODULE_COUNT; i ++)
  {
    result << extended_module_name[i] << ": " << module_time[i];
    if (global_time != 0)
    { 
      result << " (" << 100 * ((double) module_time[i]) / global_time << "%)";
    }
    result << ((i == EXTENDED_MODULE_COUNT - 1) ? "" : ", ");
  }
#undef EXTENDED_MODULE_COUNT
  return result.str();
}

void ParallelMonitor::handleSIGKILL()
{
  for (int i = 0; i < thread_num + 1; i ++)
  {
    if (current_state[i] != OUT && current_pid[i] != 0)
    {
      addTime(time(NULL));
      kill(current_pid[i], SIGKILL);
    }
  }
}
