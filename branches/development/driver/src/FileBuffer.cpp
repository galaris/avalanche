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
#include "Logger.h"

#include <string>
#include <vector>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <iostream>
#include <cerrno>

using namespace std;

static Logger *logger = Logger::getLogger();

FileBuffer::FileBuffer(std::string file_name)
{
    struct stat fileInfo;
    this->name = file_name;
    int fd = open(name.c_str(), O_RDONLY,
                  S_IRUSR | S_IROTH | S_IRGRP | S_IWUSR | S_IWOTH | S_IWGRP);
    if (fd == -1)
    {
        LOG(Logger::ERROR, "Cannot open file " << 
                           name << ": " << strerror(errno));
        throw "open";
    }
    if (fstat(fd, &fileInfo) == -1)
    {
        LOG(Logger::ERROR, name << ": " << strerror(errno));
        throw "fstat";
    }
    size = fileInfo.st_size;
    if ((buf = (char*) malloc (size + 1)) == NULL)
    {
        LOG(Logger::ERROR, strerror(errno));
        throw "malloc";
    }
    if (read(fd, buf, size) < 1)
    {
        LOG(Logger::ERROR, "Cannot read from file " <<
                          name << ": " << strerror(errno));
        throw "read";
    }
    buf[size] = '\0';
    close(fd);
}

FileBuffer::FileBuffer(const FileBuffer& other)
{
    name = other.getName();
    size = other.getSize();
    if ((buf = (char*) malloc (size + 1)) == NULL)
    {
        LOG(Logger::ERROR, strerror(errno));
        throw "malloc";
    }
    strncpy(buf, other.buf, size);
    buf[size] = '\0';
}

FileBuffer::FileBuffer(char* _buf) // it is not file_name!
{
    name = string("");
    size = strlen(_buf);
    if ((buf = (char *) malloc(size + 1)) == NULL)
    {
        LOG(Logger::ERROR, strerror(errno));
        throw "malloc";
    }
    strncpy(buf, _buf, size);
    buf[size] = '\0';
}

FileBuffer* FileBuffer::forkInput(FileBuffer *stp_file, 
                                  vector<FileOffsetSet> &used_offsets)
{
    if (stp_file->getSize() > strlen("Valid"))
    {
        if (!strncmp(stp_file->buf, "Valid", 5))
        {
            return NULL;
        }
    }
    else
    {
        return NULL;
    }
    FileBuffer* res;
    try
    {
        res = new FileBuffer(*this);
    }
    catch (const char*)
    {
        return NULL;
    }
    catch (std::bad_alloc)
    {
        LOG(Logger::ERROR, strerror(errno));
        return NULL;
    }
    if (res->applySTPSolution(stp_file->buf, used_offsets) < 0)
    {
        return NULL;
    }
    return res;
}

int FileBuffer::dumpFile(std::string file_name)
{ 
    string res_name = name;
    if (file_name != "") 
    {
        res_name = file_name;
    }
    int fd = open(res_name.c_str(), O_WRONLY | O_TRUNC | O_CREAT,
                  S_IRUSR | S_IROTH | S_IRGRP | S_IWUSR | S_IWOTH | S_IWGRP);
    if (fd == -1)
    {
        LOG(Logger::ERROR, "Cannot open file " << 
                           res_name << ": " << strerror(errno));
        return -1;
    }
    if (write(fd, buf, size) < 1)
    {
        LOG(Logger::ERROR, "Cannot write to file " << 
                           res_name << ": " << strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

int FileBuffer::cutQueryAndDump(std::string file_name, bool do_invert)
{
    char* query = strstr(buf, "QUERY(FALSE);");
    if (query == NULL)
    {
        return 0;
    }
    if (do_invert)
    {
        *(query - 4) = (*(query - 4) == '0') ? '1' : '0';
    }
    unsigned int old_size = size;
    size = (query - buf) + 13;
    if (dumpFile(file_name) < 0)
    {
        *(query - 4) = (*(query - 4) == '0') ? '1' : '0';
        return -1;
    }
    if (do_invert)
    {
        for (int k = 0; k < 13; k++)
        {
            query[k] = '\n';
        }
        *(query - 4) = (*(query - 4) == '0') ? '1' : '0';
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
    size = old_size;
}

static 
bool checkOffset(vector<FileOffsetSet> &used_offsets, 
                 string file_name, unsigned long offset)
{
  for (vector<FileOffsetSet>::iterator it = used_offsets.begin(); 
                                       it != used_offsets.end();
                                       it ++)
  {
    if (it->file_name == file_name)
    {
      if (it->offset_set.find(offset) != it->offset_set.end())
      {
        return true;
      }
    }
  }
  return false;
}


int FileBuffer::applySTPSolution(char* buf, 
                                 vector<FileOffsetSet> &used_offsets)
{
    char* pointer = buf;
    char* byte_value;
    bool use_offset_log = (used_offsets.size() != 0);
    string original_file_name;
    while ((byte_value = strstr(pointer, "file_")) != NULL)
    {
        char* brack = strchr(byte_value, '[');
        if (brack == NULL)
        {
            return -1;
        }
        *brack = '\0';
        std::string file_name(byte_value + 5);
        original_file_name = file_name;
        size_t found = file_name.find("_slash_");
        while (found != std::string::npos) 
        {
            file_name.replace(found, strlen("_slash_"), "/");
            found = file_name.find("_slash_");
        }
        found = file_name.find("_dot_");
        while (found != std::string::npos) 
        {
            file_name.replace(found, strlen("_dot_"), ".");
            found = file_name.find("_dot_");
        }
        found = file_name.find("_hyphen_");
        while (found != std::string::npos) 
        {
            file_name.replace(found, strlen("_hyphen_"), "-");
            found = file_name.find("_hyphen_");
        }
        if (name == file_name)
        {
            char* pos_begin = brack + 5;
            char* posend;
            long index = strtol(pos_begin, &posend, 16);
            if ((index < 0) || (index >= size))
            {
                return -1;
            }
            char* value_begin = posend + 9;
            long value = strtol(value_begin, &pointer, 16);
            if (checkOffset(used_offsets, original_file_name, index) ||
                !use_offset_log)
            {
                this->buf[index] = value;
            }
        }
        else
        {
            pointer = brack + 5;
        }
        *brack = '[';
    }
    return 0;
}

bool FileBuffer::filterCovgrindOutput()
{
    char* check_pid = buf;
    int eqNum = 0;
    for (;;)
    {
        if (*check_pid == '\0') return false;
        if (*check_pid == '=') eqNum ++;
        if (eqNum == 4) break;
        check_pid ++;
    }
    int skipLength = check_pid - buf + 2;
    char* bug_start = strstr(buf, "Process terminating");
    if (bug_start == NULL) return false;
    char* stack_start = strstr(bug_start, "at 0x");
    if (stack_start == NULL) return false;
    char* last_bug_line = stack_start;
    char* last_bug_sym = strchr(last_bug_line, '\n');
    if (last_bug_sym == NULL) return false;
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

// "possibly lost: ", "ERROR SUMMARY: ", "definitely lost: "
long FileBuffer::filterCount(const char * str)
{
    long number = -1;
    char * find = NULL;
    find = strstr(buf, str);

    if (find != NULL)
    {
        number = strtol(find + strlen(str), NULL, 10);
    }    
    return number;
}

// Memcheck error call stack
string FileBuffer::getMemoryErrorType(int &position)
{
  int end;

  string error_type;
    
    string str_buf = buf;
    int min_pos = INT_MAX;
    string min_error_type;
  string memory_errors [] =
  {
    " contains unaddressable byte(s)",
    "Use of uninitialised value of size",
    "Conditional jump or move depends on uninitialised value(s)",
    "Syscall param",
    " byte(s) found during client check request",
    "Invalid ",
    "Mismatched free() / delete / delete []",
    "Jump to the invalid address stated on the next line",
    "Source and destination overlap in",
    "Illegal memory pool address",
    " loss record ", 
    ""
  };

  int i = 0;
  while (!memory_errors[i].empty())
  {
    int found = string(buf).find(memory_errors[i], position);

    if (found != string::npos) // if found
    {
      int j, k;
      for (k = found; buf[k] != '='; k++);
      for (j = found; buf[j] != '='; j--);
            
            if (k < min_pos)
            {
                min_pos = k;
                min_error_type = str_buf.substr (j + 2, k - j - 3);
            }
        }
    i ++;
  }

    position = min_pos;
    return min_error_type;

}

// Memcheck error call stack

string FileBuffer::getCallStack (int & position)
{
    int end;

    string call_stack;

    // Call stack parsing

    int l;
    if (position > strlen(buf))
    {
        return "";
    } 

    for (l = position; !(buf [l] == '=' && buf [l + 2] == '\n'); l++);

    call_stack = string (buf).substr (position, l - position) + " ";

    position = l;

    // Deletion PID from Memcheck log

    int begin = 0;
    do
    {
        end = call_stack.find ("== ");
        call_stack.replace (begin, end - begin + 2, "");
        begin = call_stack.find ("==");
    }
    while (begin != string::npos);

    call_stack.at(call_stack.size() - 1) = '\n';

    return call_stack;
}

string FileBuffer::getBuf ()
{
    return string (buf);
}

bool operator == (const FileBuffer& arg1, const FileBuffer& arg2)
{
    return (strcmp(arg1.buf, arg2.buf) == 0);
}

FileBuffer::~FileBuffer()
{
    free(buf);
}

