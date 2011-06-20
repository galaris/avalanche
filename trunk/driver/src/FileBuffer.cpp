/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*----------------------------------- FileBuffer.cpp -------------------------------------*/
/*----------------------------------------------------------------------------------------*/

/*
   Copyright (C) 2009-2011 Ildar Isaev
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
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <iostream>

FileBuffer::FileBuffer(const char* name)
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

void FileBuffer::dumpFile(const char* name)
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

void FileBuffer::cutQueryAndDump(const char* name, bool do_invert)
{
  char* query = strstr(buf, "QUERY(FALSE);");
  if (do_invert)
  {
    if (query[-4] == '0')
    {
      query[-4] = '1';
    } 
    else if (query[-4] == '1')
    {
      query[-4] = '0';
    }
  }
  unsigned int oldsize = size;
  size = (query - buf) + 13;
  dumpFile(name);
  if (do_invert)
  {
    for (int k = 0; k < 13; k++)
    {
      query[k] = '\n';
    }
    if (query[-4] == '0')
    {
      query[-4] = '1';
    } 
    else if (query[-4] == '1')
    {
      query[-4] = '0';
    }
  }
  else
  {
    int k = 0;
    for (; k < 13; k++)
    {
      query[k] = '\n';
    }
    k = -1;
    while (query[k] != '\n')
    {
      query[k] = '\n';
      k--;
    }
  }
  size = oldsize;
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
    found = filename.find("_hyphen_");
    while (found != std::string::npos) 
    {
      filename.replace(found, strlen("_hyphen_"), "-");
      found = filename.find("_hyphen_");
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

bool FileBuffer::filterCovgrindOutput()
{
  char* checkPId = buf;
  int eqNum = 0;
  while (checkPId != NULL)
  {
    if (*checkPId == '=') eqNum ++;
    if (eqNum == 4) break;
    checkPId ++;
  }
  int skipLength = checkPId - buf + 2;
  char* bug_start = strstr(buf, "Process terminating");
  if (bug_start == NULL) return false;
  bug_start = strstr(bug_start, "at 0x");
  if (bug_start == NULL) return false;
  char* last_bug_line = bug_start;
  char* last_bug_sym = strchr(last_bug_line, '\n');
  if (last_bug_sym == NULL)
  {
    return false;
  }
  last_bug_line = last_bug_sym + 1;
  char* tmp,* prev_new_line = last_bug_sym;
  while (((last_bug_sym = strchr(last_bug_line, '\n')) != NULL) && ((tmp = strstr(last_bug_line, "by 0x")) != NULL) && (tmp < last_bug_sym))
  {
    prev_new_line = last_bug_sym;
    last_bug_line = last_bug_sym + 1;
  }
  last_bug_sym = prev_new_line;
  if (last_bug_sym == NULL) return false;
  if (last_bug_sym <= bug_start + 1) return false;
  char* new_buf = (char*) malloc (last_bug_sym - bug_start);
  int i = 0, j;
  while (bug_start < last_bug_sym && bug_start != NULL)
  {
    if (*bug_start == '=')
    {
      bug_start += skipLength;
      continue;
    }
    new_buf[i ++] = *bug_start;
    bug_start ++;
  }
  free(buf);
  buf = (char*) malloc(i + 1);
  for (j = 0; j < i; j ++)
  {
    buf[j] = new_buf[j];
  }
  buf[j] = '\0';
  size = i;
  free(new_buf);
  return true;
}

bool operator == (const FileBuffer& arg1, const FileBuffer& arg2)
{
  return (strcmp(arg1.buf, arg2.buf) == 0);
}

FileBuffer::~FileBuffer()
{
  free(buf);
  free(name);
}

