
/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*------------------------------------- Chunk.cpp ----------------------------------------*/
/*----------------------------------------------------------------------------------------*/

/*
   Copyright (C) 2010 Ildar Isaev
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

#include "Chunk.h"
#include "FileBuffer.h"
#include "Logger.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <vector>
#include <iostream>

using namespace std;

static Logger* logger = Logger::getLogger();

Chunk::Chunk(FileBuffer* trace, int exploitNum, int inputNum)
{
  if (trace == NULL)
  {
    this->trace = NULL;
  }
  else
  {
    this->trace = new FileBuffer(*trace);
  }
  exploitGroups.push_back(make_pair(exploitNum, inputNum));
}

Chunk::~Chunk()
{
  delete trace;
}

void Chunk::addGroup(int exploitNum, int inputNum)
{
  exploitGroups.push_back(make_pair(exploitNum, inputNum));
}
  
FileBuffer* Chunk::getTrace()
{
  return trace;
}

void Chunk::print(string prefix, int chunkNum, int fd)
{
  ostringstream out;
  out << "chunk " << chunkNum << ": ";
  for (vector<pair<int, int> >::iterator it = exploitGroups.begin(); it != exploitGroups.end(); it++)
  {
    if (it != exploitGroups.begin())
    {
      out << ", ";
    }
    int exploitNum = it->first;
    int inputNum = it->second;
    if (inputNum != -1)
    {
      for (int i = 0; i < inputNum - 1; i++)
      {
        out << prefix << "exploit_" << exploitNum << "_" << i << " + ";
      }
      out << prefix << "exploit_" << exploitNum << "_" << inputNum - 1;
    }
    else
    {
      out << prefix << "exploit_" << exploitNum;
    }
  }
  if (trace != NULL)
  {
    out << " - " << prefix << "stacktrace_" << chunkNum << ".log";
  }
  else
  {
    out << " - No stack trace available";
  }
  if (fd == -1)
  {
    REPORT(logger, out.str());
  }
  else
  {
    out << "\n";
    string output = out.str();
    write(fd, output.c_str(), output.length());
  }
}

