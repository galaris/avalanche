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
#include "ExecutionManager.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

using namespace std;

Input::Input()
{
  this->startdepth = 0;
  this->prediction = NULL;
  this->predictionSize = 0;
  this->parent = NULL;
}

Input::~Input()
{
  if (prediction != NULL)
  {
    delete []prediction;
  }
  for (int i = 0; i < files.size(); i ++)
  {
    delete (files.at(i));
  }
}

void Input::dumpExploit(string file_name, bool predict, string name_modifier)
{
  std::string res_name = file_name + name_modifier;
  int fd = open(res_name.c_str(), O_WRONLY | O_TRUNC | O_CREAT,
                S_IRUSR | S_IROTH | S_IRGRP | S_IWUSR | S_IWOTH | S_IWGRP);
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
    string prediction_file = ExecutionManager::getTempDir() + 
                             string("prediction.log");
    int fd = open(prediction_file.c_str(), O_WRONLY | O_TRUNC | O_CREAT, 
                  S_IRUSR | S_IROTH | S_IRGRP | S_IWUSR | S_IWOTH | S_IWGRP);
    write(fd, prediction, predictionSize * sizeof(bool));
    close(fd);
  }  
}

void Input::dumpFiles(string name_modifier)
{
  for (int i = 0; i < files.size(); i++)
  {
    string res_name = string(files.at(i)->name) + name_modifier;
    files.at(i)->dumpFile(res_name);
  }
  if (prediction != NULL)
  {
    string prediction_file = ExecutionManager::getTempDir() +
                             string("prediction.log");
    int fd = open(prediction_file.c_str(), O_WRONLY | O_TRUNC | O_CREAT,
                  S_IRUSR | S_IROTH | S_IRGRP | S_IWUSR | S_IWOTH | S_IWGRP);
    write(fd, prediction, predictionSize * sizeof(bool));
    close(fd);
  }
}
