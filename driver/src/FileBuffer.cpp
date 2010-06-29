
/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*----------------------------------- FileBuffer.cpp -------------------------------------*/
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

#include "FileBuffer.h"

#include <cstddef>
#include <string>

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

FileBuffer::FileBuffer(char* name)
{
  this->name = strdup(name);
  int fd = open(name, O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
  struct stat fileInfo;
  fstat(fd, &fileInfo);
  size = fileInfo.st_size;
  buf = (char*) malloc (size + 1);
  read(fd, buf, size);
  buf[size] = '\0';
  close(fd);
}

FileBuffer::FileBuffer(const FileBuffer& other)
{
  this->name = strdup(other.name);
  this->size = other.size;
  this->buf = (char*) malloc (size + 1);
  for (int i = 0; i < size + 1; i++)
  {
    this->buf[i] = other.buf[i];
  }
}

FileBuffer* FileBuffer::forkInput(char* stpOutputFile)
{
  FileBuffer stp(stpOutputFile);
  if ((stp.buf[0] == 'V') && (stp.buf[1] == 'a') && (stp.buf[2] == 'l') && (stp.buf[3] == 'i') && (stp.buf[4] == 'd'))
  {
    return NULL;
  } 
  FileBuffer* res = new FileBuffer(*this);
  res->applySTPSolution(stp.buf);
  return res;
}

void FileBuffer::dumpFile(char* name)
{  
  int fd;
  if (name == NULL)
  {
    fd = open(this->name, O_RDWR | O_TRUNC | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
  }
  else
  {
    fd = open(name, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
  }
  write(fd, buf, size);
  close(fd);
}
  
void FileBuffer::applySTPSolution(char* buf)
{
  char* pointer = buf;
  char* byteValue;
  while ((byteValue = strstr(pointer, "file_")) != NULL)
  {
    char* brack = strchr(byteValue, '[');
    *brack = '\0';
    std::string filename(byteValue + 5);
    size_t found = filename.find("_slash_");
    while (found != std::string::npos) 
    {
      filename.replace(found, strlen("_slash_"), "/");
      found = filename.find("_slash_");
    }
    found = filename.find("_dot_");
    while (found != std::string::npos) 
    {
      filename.replace(found, strlen("_dot_"), ".");
      found = filename.find("_dot_");
    }
    if (!strcmp(this->name, filename.c_str()))
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

FileBuffer::~FileBuffer()
{
  free(buf);
  free(name);
}

