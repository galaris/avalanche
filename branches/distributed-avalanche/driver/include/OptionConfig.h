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
    OptionConfig(): reportLog(NULL),
                    debug(false),
                    protectMainAgent(false),
                    STPThreadsAuto(false),
		    checkDanger(false),
                    verbose(false),
		    sockets(false),
		    traceChildren(false),
                    datagrams(false),
                    distributed(false), 
                    agent(false), 
                    useMemcheck(false),
                    suppressSubcalls(false),
                    dumpCalls(false),
                    leaks(false),
                    funcFilterFile(std::string("")),
                    depth(100),
                    startdepth(1),
                    alarm(300),
                    tracegrindAlarm(0),
                    host(std::string("")),
                    prefix(std::string("")),
                    disthost(std::string("127.0.0.1")),
                    port(65536),
                    distport(10000),
                    STPThreads(0)
    {}

    OptionConfig(const OptionConfig *opt_config)
    {
        reportLog       = opt_config->reportLog;
        traceChildren   = opt_config->traceChildren;
        debug           = opt_config->debug;
        protectMainAgent= opt_config->protectMainAgent;
        distributed     = opt_config->distributed;
        agent           = opt_config->agent;
        checkDanger     = opt_config->checkDanger;
        verbose         = opt_config->verbose;
        sockets         = opt_config->sockets;
        datagrams       = opt_config->datagrams;
        depth           = opt_config->depth;
        startdepth      = opt_config->startdepth;
        valgrind        = opt_config->valgrind;
        prog_and_arg    = opt_config->prog_and_arg;
        files           = opt_config->files;
        alarm           = opt_config->alarm;
        tracegrindAlarm = opt_config->tracegrindAlarm;
        host	        = opt_config->host;
        port	        = opt_config->port;
        disthost	= opt_config->disthost;
        distport	= opt_config->distport;
        useMemcheck     = opt_config->useMemcheck;
        leaks           = opt_config->leaks;
        funcFilterFile  = opt_config->funcFilterFile;
        funcFilterUnits = opt_config->funcFilterUnits;
        suppressSubcalls= opt_config->suppressSubcalls;
        dumpCalls       = opt_config->dumpCalls;
        inputFilterFile = opt_config->inputFilterFile;
        STPThreads	= opt_config->STPThreads;
        STPThreadsAuto	= opt_config->STPThreadsAuto;
        prefix          = opt_config->prefix;
    }

    bool empty() const
    { return prog_and_arg.empty(); }

    void setValgrind(const std::string &dir)
    { valgrind = dir; }
    
    const std::string &getValgrind() const
    { return valgrind; }

    void setFuncFilterFile(const std::string &fileName)
    { funcFilterFile = fileName; }
    
    const std::string getFuncFilterFile() const
    { return funcFilterFile; }

    void setInputFilterFile(const std::string &fileName)
    { inputFilterFile = fileName; }
    
    const std::string getInputFilterFile() const
    { return inputFilterFile; }

    char* getReportLog() const
    { return reportLog; }

    void setReportLog(char* reportLog)
    { this->reportLog = reportLog; }

    void setDebug()
    { debug = true; }
    
    bool getDebug() const
    { return debug; }

    void setSTPThreadsAuto()
    { STPThreadsAuto = true; }
    
    bool getSTPThreadsAuto() const
    { return STPThreadsAuto; }

    void setTraceChildren()
    { traceChildren = true; }
    
    bool getTraceChildren() const
    { return traceChildren; }

    void setProtectMainAgent()
    { protectMainAgent = true; }

    bool getProtectMainAgent() const
    { return protectMainAgent; }

    void setDumpCalls()
    { dumpCalls = true; }

    bool getDumpCalls() const
    { return dumpCalls; }

    bool getSuppressSubcalls() const
    { return suppressSubcalls; }

    void setSuppressSubcalls()
    { suppressSubcalls = true; }
     
    void setVerbose()
    { verbose = true; }
    
    bool getVerbose() const
    { return verbose; }

    void setDistributed()
    { distributed = true; }
    
    bool getDistributed() const
    { return distributed; }

    void setAgent()
    { agent = true; }

    void setNotAgent()
    { agent = false; }
    
    bool getAgent() const
    { return agent; }

    void setSTPThreads(int num)
    { STPThreads = num; }
    
    int getSTPThreads() const
    { return STPThreads; }

    void setStartdepth(int startdepth)
    { this->startdepth = startdepth; }
    
    int getStartdepth() const
    { return startdepth; }

    void setCheckDanger()
    { checkDanger = true; }
    
    bool getCheckDanger() const
    { return checkDanger; }

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

    void addFuncFilterUnit(const std::string &fn)
    { funcFilterUnits.push_back(fn); }

    const std::vector<std::string> getfuncFilterUnits() const
    { return funcFilterUnits; }
  
    std::string getFuncFilterUnit(int i)
    { return funcFilterUnits.at(i); }

    int getFuncFilterUnitsNum()
    { return funcFilterUnits.size(); }

    void setTracegrindAlarm(unsigned int alarm)
    { this->tracegrindAlarm = alarm; }

    unsigned int getTracegrindAlarm() const
    { return tracegrindAlarm; }

    void setPort(unsigned int port)
    { this->port = port; }

    unsigned int getPort() const
    { return port; }

    void setDistPort(int port)
    { distport = port; }

    int getDistPort() const
    { return distport; }

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

    std::string getPrefix()
    { return prefix; }

    void setPrefix(std::string& prefix)
    { this->prefix = prefix; }

    std::string getDistHost()
    { return disthost; }

    void setDistHost(std::string& host)
    { disthost = host; }

private:
    char*                    reportLog;
    bool                     debug;
    bool                     protectMainAgent;
    bool                     verbose;
    bool		     sockets;
    bool                     datagrams;
    bool                     useMemcheck;
    bool                     checkDanger;
    bool                     leaks;
    bool                     suppressSubcalls;
    bool                     dumpCalls;
    bool 		     traceChildren;
    bool                     distributed;
    bool                     agent;
    bool                     STPThreadsAuto;
    std::string              funcFilterFile;
    std::size_t              depth;
    std::string              valgrind;
    std::vector<std::string> prog_and_arg;
    std::vector<std::string> files;
    unsigned int             alarm;
    unsigned int             tracegrindAlarm;
    std::string		     host;
    std::string              disthost;
    unsigned int	     port;
    unsigned int             distport;
    std::vector<std::string> funcFilterUnits;
    std::string              inputFilterFile;
    std::string              prefix;
    int                      startdepth;
    int                      STPThreads;
};


#endif //__OPTION_CONFIG__H__

