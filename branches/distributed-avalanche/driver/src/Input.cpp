
/*----------------------------------------------------------------------------------------*/
/*------------------------------------- AVALANCHE ----------------------------------------*/
/*------ Driver. Coordinates other processes, traverses conditional jumps tree.  ---------*/
/*------------------------------------- Input.cpp ----------------------------------------*/
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

#include "Input.h"
#include "FileBuffer.h"

#include <cstddef>
#include <string>

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

Input::Input()
{
  this->startdepth = 0;
  this->prediction = NULL;
  this->predictionSize = 0;
  this->parent = NULL;
}

void Input::dumpExploit(char* name, bool predict)
{
  int fd = open(name, O_RDWR | O_TRUNC | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
  int size = files.size();
  write(fd, &size, sizeof(int));
  for (int i = 0; i < files.size(); i++)
  {
    write(fd, &(files.at(i)->size), sizeof(int));
    write(fd, files.at(i)->buf, files.at(i)->size);
  }
  close(fd);
  if (predict && (prediction != NULL))
  {
    int fd = open("prediction.log", O_RDWR | O_TRUNC | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
    write(fd, prediction, predictionSize * sizeof(bool));
    close(fd);
  }  
}

void Input::dumpFiles(char* name)
{
  for (int i = 0; i < files.size(); i++)
  {
    files.at(i)->dumpFile(name);
  }
  if ((prediction != NULL) && (name == NULL))
  {
    int fd = open("prediction.log", O_RDWR | O_TRUNC | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
    write(fd, prediction, predictionSize * sizeof(bool));
    close(fd);
  }
}
