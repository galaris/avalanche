// $Id: OptionConfig.h 80 2009-10-30 18:55:50Z iisaev $
/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*---------------------------------- OptionConfig.h --------------------------------------*/
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

#ifndef __OPTION_CONFIG__H__
#define __OPTION_CONFIG__H__

#include <cstddef>
#include <vector>
#include <string>


class OptionConfig
{
public:
    OptionConfig(): debug(false),
                    verbose(false),
		    sockets(false),
                    datagrams(false),
                    useMemcheck(false),
                    suppressSubcalls(false),
                    leaks(false),
                    funcFilter(std::string("")),
                    depth(100),
                    alarm(300),
                    funcAddr(0),
                    tracegrindAlarm(0),
                    host(std::string("")),
                    port(65536) 
    {}

    OptionConfig(const OptionConfig *opt_config)
    {
        debug           = opt_config->debug;
        verbose         = opt_config->verbose;
        sockets         = opt_config->sockets;
        datagrams       = opt_config->datagrams;
        depth           = opt_config->depth;
        valgrind        = opt_config->valgrind;
        prog_and_arg    = opt_config->prog_and_arg;
        files           = opt_config->files;
        alarm           = opt_config->alarm;
        tracegrindAlarm = opt_config->tracegrindAlarm;
        host	        = opt_config->host;
        port	        = opt_config->port;
        useMemcheck     = opt_config->useMemcheck;
        leaks           = opt_config->leaks;
        funcFilter      = opt_config->funcFilter;
        funcAddr        = opt_config->funcAddr;
        suppressSubcalls= opt_config->suppressSubcalls;
    }

    bool empty() const
    { return prog_and_arg.empty(); }

    void setValgrind(const std::string &dir)
    { valgrind = dir; }
    
    const std::string &getValgrind() const
    { return valgrind; }

    void setFuncFilter(const std::string &filter)
    { funcFilter = filter; }
    
    const std::string getFuncFilter() const
    { return funcFilter; }

    void setDebug()
    { debug = true; }
    
    bool getDebug() const
    { return debug; }

    bool getSuppressSubcalls() const
    { return suppressSubcalls; }

    void setSuppressSubcalls()
    { suppressSubcalls = true; }
     
    void setVerbose()
    { verbose = true; }
    
    bool getVerbose() const
    { return verbose; }

    void setUsingSockets()
    { sockets = true; }
    
    bool usingSockets() const
    { return sockets; }

    void setUsingDatagrams()
    { datagrams = true; }
    
    bool usingDatagrams() const
    { return datagrams; }

    void setLeaks()
    { leaks = true; }
    
    bool checkForLeaks() const
    { return leaks; }

    void setUsingMemcheck()
    { useMemcheck = true; }
    
    bool usingMemcheck() const
    { return useMemcheck; }

    void setDepth(std::size_t max_depth)
    { depth = max_depth; }

    std::size_t getDepth() const
    { return depth; }

    void setAlarm(unsigned int alarm)
    { this->alarm = alarm; }

    unsigned int getAlarm() const
    { return alarm; }

    void setFuncAddr(unsigned long long int addr)
    { this->funcAddr = addr; }

    unsigned long long int getFuncAddr() const
    { return funcAddr; }

    void setTracegrindAlarm(unsigned int alarm)
    { this->tracegrindAlarm = alarm; }

    unsigned int getTracegrindAlarm() const
    { return tracegrindAlarm; }

    void setPort(unsigned int port)
    { this->port = port; }

    unsigned int getPort() const
    { return port; }

    void addProgAndArg(const std::string &arg)
    { prog_and_arg.push_back(arg); }

    const std::vector<std::string> &getProgAndArg() const
    { return prog_and_arg; }
  
    std::string getFile(int i)
    { return files.at(i); }

    int getNumberOfFiles()
    { return files.size(); }

    void addFile(std::string& filename)
    { files.push_back(filename); }

    std::string getHost()
    { return host; }

    void setHost(std::string& host)
    { this->host = host; }

private:
    bool                     debug;
    bool                     verbose;
    bool		     sockets;
    bool                     datagrams;
    bool                     useMemcheck;
    bool                     leaks;
    bool                     suppressSubcalls;
    std::string              funcFilter;
    std::size_t              depth;
    std::string              valgrind;
    std::vector<std::string> prog_and_arg;
    std::vector<std::string> files;
    unsigned int             alarm;
    unsigned int             tracegrindAlarm;
    std::string		     host;
    unsigned int	     port;
    unsigned long long int   funcAddr;
};


#endif //__OPTION_CONFIG__H__

