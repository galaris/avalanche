
/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*---------------------------------- SocketBuffer.cpp ------------------------------------*/
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

#include "SocketBuffer.h"

#include <cstddef>
#include <string>

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

SocketBuffer::SocketBuffer(int num, int size)
{
  this->name = NULL;
  this->num = num;
  this->size = size;
  this->buf = (char*) malloc (this->size);
  memset(this->buf, 0, this->size);
}

SocketBuffer::SocketBuffer(const SocketBuffer& other)
{
  this->name = NULL;
  this->num = other.num;
  this->size = other.size;
  this->buf = (char*) malloc (size);
  for (int i = 0; i < size; i++)
  {
    this->buf[i] = other.buf[i];
  }
}

FileBuffer* SocketBuffer::forkInput(char* stpOutputFile)
{
  FileBuffer stp(stpOutputFile);
  if ((stp.buf[0] == 'V') && (stp.buf[1] == 'a') && (stp.buf[2] == 'l') && (stp.buf[3] == 'i') && (stp.buf[4] == 'd'))
  {
    return NULL;
  } 
  SocketBuffer* res = new SocketBuffer(*this);
  res->applySTPSolution(stp.buf);
  return res;
}

void SocketBuffer::dumpFile(char* name)
{  
}
  
void SocketBuffer::applySTPSolution(char* buf)
{
  char* pointer = buf;
  char* byteValue;
  while ((byteValue = strstr(pointer, "socket_")) != NULL)
  {
    char* brack = strchr(byteValue, '[');
    *brack = '\0';
    int number = atoi(byteValue + 7);
    if (this->num == number)
    {
      char* posbegin = brack + 5;
      char* posend;
      long index = strtol(posbegin, &posend, 16);
      char* valuebegin = posend + 9;
      long value = strtol(valuebegin, &pointer, 16);
      this->buf[index] = value;
    }
    else
    {
      pointer = brack + 5;
    }
  }
}

SocketBuffer::~SocketBuffer()
{
  free(buf);
}

