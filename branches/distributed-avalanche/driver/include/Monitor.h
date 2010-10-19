/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*------------------------------------- Monitor.h ----------------------------------------*/
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

#ifndef _MONITOR_H
#define _MONITOR_H

#include <string>
#include <iostream>
#include <set>
#include <utility>

#define MODULE_COUNT 3

enum state {TRACER = 0, CHECKER, STP, OUT};
enum output {TRACER_OUTPUT = 0, CHECKER_OUTPUT, STP_OUTPUT, CHECKER_AND_STP_OUTPUT };

typedef std::pair<time_t, time_t> interval;

class Monitor
{
  protected:
            bool is_killed;
            std::string module_name[MODULE_COUNT];
  public: 
            Monitor(std::string checker_name);
            ~Monitor() {}
            virtual void setState(state _state, time_t _start_time, unsigned int thread_index = 0) = 0;
            virtual void setPID(pid_t _pid, unsigned int thread_index = 0) = 0;
            virtual void addTime(time_t end_time, unsigned int thread_index = 0) = 0;
            virtual std::string getStats(time_t global_time = 0) = 0;
            virtual state getCurrentState(unsigned int thread_index = 0) = 0;
            virtual void handleSIGKILL() = 0;
            virtual void handleSIGALARM() = 0;
            bool getKilledStatus() { return is_killed; }
            void setKilledStatus(bool _is_killed) { is_killed = _is_killed; }
};

class SimpleMonitor : public Monitor
{
  private:
            time_t start_time;
            state current_state;
            pid_t current_pid;
            time_t module_time[MODULE_COUNT];
  public:
            SimpleMonitor(std::string checker_name);
            ~SimpleMonitor() {}
            void setState(state _state, time_t _start_time, unsigned int thread_index = 0)
            {
              current_state = _state;
              start_time = _start_time;
            }

            void setPID(pid_t _pid, unsigned int thread_index = 0)
            {
              current_pid = _pid;
            }
            void addTime(time_t end_time, unsigned int thread_index = 0);
          
            std::string getStats(time_t global_time = 0);
            
            state getCurrentState(unsigned int thread_index = 0) { return current_state; }
            void handleSIGKILL();
            void handleSIGALARM();
};

class ParallelMonitor : public Monitor
{
  private:
            unsigned int thread_num;
            time_t time_shift;

            state* current_state;
            pid_t* current_pid;
            bool* alarm_killed;

            time_t* checker_start_time;
            time_t* stp_start_time;
            time_t tracer_start_time;

            std::set <interval> checker_time;
            std::set <interval> stp_time;
            time_t tracer_time;
            time_t checker_alarm;
            time_t tracer_alarm;
  public:
            ParallelMonitor(std::string checker_name, unsigned int _thread_num, time_t _time_shift); 
            ~ParallelMonitor();

            void setAlarm(time_t _checker_alarm, time_t _tracer_alarm)
            {
              checker_alarm = _checker_alarm;
              tracer_alarm = _tracer_alarm;
            }

            bool getAlarmKilled(unsigned int thread_index = 0) { return alarm_killed[thread_index - 1]; }

            void setState(state _state, time_t _start_time, unsigned int thread_index = 0);

            void setPID(pid_t _pid, unsigned int thread_index = 0)
            {
              current_pid[thread_index] = _pid;
            }
            
            void addTime(time_t end_time, unsigned int thread_index = 0);
           
            std::string getStats(time_t global_time = 0);
             
            state getCurrentState(unsigned int thread_index = 0) { return current_state[thread_index]; }
            
            void handleSIGALARM();

            void handleSIGKILL();
};
 
#endif
