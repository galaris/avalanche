/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*-------------------------------------- Logger.h ----------------------------------------*/
/*----------------------------------------------------------------------------------------*/

/*
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

#ifndef __LOGGER__H__
#define __LOGGER__H__

#include <cstddef>
#include <sstream>
#include <string>


class Logger
{
public:
    enum Level { LEV_ALWAYS, LEV_INFO, LEV_DEBUG, LEV_ERROR, LEV_NET };

    Logger(): enable_verbose(false)
    {}

    void enableVerbose()
    { enable_verbose = true; }
    
    static Logger *getLogger();

    void write(Level level,
               const std::string &msg,
               const char *file, std::size_t line) const;

private:
    bool enable_verbose;
};

#define REPORT(logger, msg) \
    do { \
        std::ostringstream log_buf; \
        log_buf << msg; \
        logger->write(Logger::LEV_ALWAYS, log_buf.str(), __FILE__, __LINE__);\
    } while (0)

#define NET(logger, msg) \
    do { \
        std::ostringstream log_buf; \
        log_buf << msg; \
        logger->write(Logger::LEV_NET, log_buf.str(), __FILE__, __LINE__);\
    } while (0)

#define LOG(logger, msg) \
    do { \
        std::ostringstream log_buf; \
        log_buf << msg; \
        logger->write(Logger::LEV_INFO, log_buf.str(), __FILE__, __LINE__);\
    } while (0)

#define DBG(logger, msg) \
    do { \
        std::ostringstream log_buf; \
        log_buf << msg; \
        logger->write(Logger::LEV_DEBUG, log_buf.str(), __FILE__, __LINE__);\
    } while (0)

#define ERR(logger, msg) \
    do { \
        std::ostringstream log_buf; \
        log_buf << msg; \
        logger->write(Logger::LEV_ERROR, log_buf.str(), __FILE__, __LINE__);\
    } while (0)


#endif //__LOGGER__H__

