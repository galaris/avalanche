/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*------------------------------------- Thread.h -----------------------------------------*/
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

#ifndef _THREAD_H
#define _THREAD_H

#include <pthread.h>
#include <iostream>
#include <map>
#include <string>

class Thread;

struct data_wrapper
{
  Thread* this_pointer;
  void* data;
};

struct pool_data
{
  void* (*work_func) (void*);
  void* data;
};

struct shared_data_unit
{
  pthread_mutex_t* mutex;
  void* data_unit;
};

class Thread
{
  protected:
           std::map <std::string, void*> private_data;
           std::map <std::string, void*> readonly_data;
           std::map <std::string, shared_data_unit> shared_data;
           pthread_t tid;
           int user_tid;
  public:
           Thread() : tid(0), user_tid(-1) {}
           Thread(pthread_t _tid, int _user_tid) : tid(_tid), user_tid(_user_tid) {}
           ~Thread() {}

           void setCustomTID(int _tid) { user_tid = _tid; }

           static void* createAndRun(void* input)
           {
             void* data = ((data_wrapper*) input)->data;
             Thread* this_pointer = ((data_wrapper*) input)->this_pointer;
             delete ((data_wrapper*)input);
             this_pointer->doWork(data);
           }

           int createThread(void* data, bool is_joinable = true);

           void addPrivateDataUnit(void* _data_unit, std::string name) { private_data[name] = _data_unit; }
           void clearPrivateData() { private_data.clear(); }
           void addSharedDataUnit(void* _data_unit, std::string name, pthread_mutex_t* _mutex = NULL);
           void clearSharedData() { readonly_data.clear(); shared_data.clear(); }

           void* getPrivateDataUnit(std::string name) { return private_data[name]; }
           void* getReadonlyDataUnit(std::string name) { return readonly_data[name]; }
           shared_data_unit getSharedDataUnit(std::string name) { return shared_data[name]; }

           virtual void doWork(void* data) {}
           int waitForThread() { return pthread_join(tid, NULL); }
           void printMessage(const char* message, bool show_real_tid = false);
           int getCustomTID() { return user_tid; }
           pthread_t getTID() { return tid; }

};

class PoolThread : public Thread
{
  private:
           pthread_mutex_t* work_finish_mutex;
           pthread_cond_t* work_finish_cond;
           int* thread_status;
           int* active_threads;
  public:
           PoolThread() : work_finish_mutex(NULL), work_finish_cond(NULL), thread_status(NULL), active_threads(NULL) {}
           ~PoolThread() {}
           
           void setPoolSync(pthread_mutex_t* _mutex, pthread_cond_t* _cond, int* _status, int* _active_threads)
           {
             work_finish_mutex = _mutex;
             work_finish_cond = _cond;
             thread_status = _status;
             active_threads = _active_threads;
           }
           
           int getStatus() 
           { 
             if (thread_status != NULL) 
               return *thread_status;
             return -1;
           }
           void doWork(void* data);
};

#endif
