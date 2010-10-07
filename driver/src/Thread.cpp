#include "Thread.h"
#include <stdlib.h>

int Thread::createThread(void* data, bool is_joinable)
{
  int ret_code;
  pthread_attr_t attr;
  data_wrapper* input = new data_wrapper;
  input->this_pointer = this;
  input->data = data;
  pthread_attr_init(&attr);
  if (is_joinable)
  {
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
  }
  else
  {
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  }
  ret_code = pthread_create(&tid, &attr, Thread::createAndRun, input);
  pthread_attr_destroy(&attr);
  return ret_code;
}

void Thread::printMessage(const char* message, bool show_real_tid)
{
  std::cout << "thread #" << user_tid;
  if (show_real_tid)
  {
    std::cout << "(" << tid << ")";
  }
  std::cout << ": " << message << std::endl; 
}

void Thread::addSharedDataUnit(void* _data_unit, std::string name, pthread_mutex_t* _mutex)
{
  if(_mutex != NULL)
  {
    shared_data_unit new_data_unit;
    new_data_unit.mutex = _mutex;
    new_data_unit.data_unit = _data_unit;
    shared_data[name] = new_data_unit;
  }
  else
  {
    readonly_data[name] = _data_unit;
  }
}

void PoolThread::doWork(void* data)
{
  (((pool_data*) data)->work_func) (((pool_data*) data)->data);
  pthread_mutex_lock(work_finish_mutex);
  (*thread_status) = 1;
  (*active_threads) ++;
  pthread_cond_signal(work_finish_cond);
  pthread_mutex_unlock(work_finish_mutex);
  pthread_exit(NULL);
}
