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
  private:
           std::map <std::string, void*> private_data;
           std::map <std::string, void*> readonly_data;
           std::map <std::string, shared_data_unit> shared_data;
           pthread_t tid;
           int user_tid;
           bool status;
  public:
           Thread() : tid(0), user_tid(-1), status(false) {}
           Thread(pthread_t _tid, int _user_tid) : tid(_tid), user_tid(_user_tid) {}
           ~Thread() {}

           void setCustomTID(int _tid) { user_tid = _tid; }

           static void* createAndRun(void* input)
           {
             ((Thread*) (((data_wrapper*) input)->this_pointer))->doWork(((data_wrapper*) input)->data);
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
           int waitForThread() { status = false; return pthread_join(tid, NULL); }
           void printMessage(const char* message, bool show_real_tid = false);
           int getCustomTID() { return user_tid; }
           pthread_t getTID() { return tid; }

           void activateThread() { status = true; }
           void deactivateThread() { status = false; }

           bool isActive() { return status; }
};

class PoolThread : public Thread
{
  private:
           pthread_mutex_t* work_finish_mutex;
           pthread_cond_t* work_finish_cond;
           int* thread_status;
           int* active_threads;
  public:
           PoolThread() {}
           ~PoolThread() {}
           
           void setPoolSync(pthread_mutex_t* _mutex, pthread_cond_t* _cond, int* _status, int* _active_threads)
           {
             work_finish_mutex = _mutex;
             work_finish_cond = _cond;
             thread_status = _status;
             active_threads = _active_threads;
           }
           
           void doWork(void* data);
};
