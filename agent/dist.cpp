/* Server code in C */
 
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <vector>
#include <set>

using namespace std;
 
int main(int argc, char** argv)
{
  struct sockaddr_in stSockAddr;
  int sfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

  if(sfd == -1)
  {
    perror("can not create socket");
    exit(EXIT_FAILURE);
  }
 
  memset(&stSockAddr, 0, sizeof(struct sockaddr_in));
 
  stSockAddr.sin_family = AF_INET;
  stSockAddr.sin_port = htons(atoi(argv[1]));
  stSockAddr.sin_addr.s_addr = INADDR_ANY;

  int bindRes = bind(sfd, (const struct sockaddr*)&stSockAddr, sizeof(struct sockaddr_in));
 
  if(bindRes == -1)
  {
    perror("error bind failed");
    close(sfd);
    exit(EXIT_FAILURE);
  }

  int listenRes = listen(sfd, 10);
 
  if(listenRes == -1)
  {
    perror("error listen failed");
    close(sfd);
    exit(EXIT_FAILURE);
  }

  vector<int> fds;

  //int free = -1;
  int mainfd = -1;
  set<int> starvating_a;
  set<int> starvating_g;

  bool gameBegan = false;
 
  for(;;)
  {

    fd_set readfds;
    int max_d = sfd;
    FD_ZERO(&readfds);
    FD_SET(sfd, &readfds);

    for (vector<int>::iterator fd = fds.begin(); fd != fds.end(); fd++)
    {
      FD_SET(*fd, &readfds);
      if (*fd > max_d) 
      {
        max_d = *fd;
      }
    }

    //struct timeval timer;
    //timer.tv_sec = 0;
    //timer.tv_usec = 0;

    if (gameBegan)
    {
      printf("iterating through starvated\n");
      for (set<int>::iterator fd = starvating_a.begin(); fd != starvating_a.end();)
      {
        write(mainfd, "a", 1);
        printf("sent all from %d to %d\n", *fd, mainfd);
        int namelength, length, startdepth, invertdepth, alarm, tracegrindAlarm, threads, argsnum;
        bool useMemcheck, leaks, traceChildren, checkDanger, debug, verbose, sockets, datagrams, suppressSubcalls;
        int res = read(mainfd, &namelength, sizeof(int));
        if (res == 0)
        {
          printf("job is done\n");
          if (shutdown(sfd, SHUT_RDWR) == -1)
          {
            perror("shutdown failed");
          }
          close(sfd);
          exit(0);
        }
        printf("namelength=%d\n", namelength);
        if (namelength > 0)
        {
          write(*fd, &namelength, sizeof(int));
          char buf[128];
          read(mainfd, buf, namelength);
          printf("buf=%s\n", buf);
          write(*fd, buf, namelength);
          read(mainfd, &length, sizeof(int));
          printf("length=%d\n", length);
          write(*fd, &length, sizeof(int));
          char* file = new char[length];
          int received = 0;
          while (received < length)
          {
            received += read(mainfd, file + received, length - received);
          }
          for (int j = 0; j < length; j++)
          {
            printf("%x", file[j]);
          }
          write(*fd, file, length);
          read(mainfd, &startdepth, sizeof(int));
          write(*fd, &startdepth, sizeof(int));
          read(mainfd, &invertdepth, sizeof(int));
          write(*fd, &invertdepth, sizeof(int));
          read(mainfd, &alarm, sizeof(int));
          write(*fd, &alarm, sizeof(int));
          read(mainfd, &tracegrindAlarm, sizeof(int));
          printf("tracegrindAlarm=%d\n", tracegrindAlarm);
          write(*fd, &tracegrindAlarm, sizeof(int));
          read(mainfd, &threads, sizeof(int));
          write(*fd, &threads, sizeof(int));
          read(mainfd, &argsnum, sizeof(int));
          printf("argsnum=%d\n", argsnum);
          write(*fd, &argsnum, sizeof(int));

          read(mainfd, &useMemcheck, sizeof(bool));
          write(*fd, &useMemcheck, sizeof(bool));
          read(mainfd, &leaks, sizeof(bool));
          write(*fd, &leaks, sizeof(bool));
          read(mainfd, &traceChildren, sizeof(bool));
          write(*fd, &traceChildren, sizeof(bool));
          read(mainfd, &checkDanger, sizeof(bool));
          write(*fd, &checkDanger, sizeof(bool));
          read(mainfd, &debug, sizeof(bool));
          write(*fd, &debug, sizeof(bool));
          read(mainfd, &verbose, sizeof(bool));
          write(*fd, &verbose, sizeof(bool));
          read(mainfd, &sockets, sizeof(bool));
          write(*fd, &sockets, sizeof(bool));
          read(mainfd, &datagrams, sizeof(bool));
          write(*fd, &datagrams, sizeof(bool));
          read(mainfd, &suppressSubcalls, sizeof(bool));
          write(*fd, &suppressSubcalls, sizeof(bool));

          if (sockets)
          {
            int length;
            read(mainfd, &length, sizeof(int));
            write(*fd, &length, sizeof(int));
            read(mainfd, buf, length);
            write(*fd, buf, length);
            int port;
            read(mainfd, &port, sizeof(int));
            write(*fd, &port, sizeof(int));
          }

          int masklength;
          read(mainfd, &masklength, sizeof(int));
          write(*fd, &masklength, sizeof(int));
          if (masklength != 0)
          {
            char* mask = new char[masklength];
            read(mainfd, mask, masklength);
            write(*fd, mask, masklength);
            delete[] mask;
          }

          int filtersNum;
          read(mainfd, &filtersNum, sizeof(int));
          write(*fd, &filtersNum, sizeof(int));
          for (int i = 0; i < filtersNum; i++)
          {
            int length; 
            read(mainfd, &length, sizeof(int));
            write(*fd, &length, sizeof(int));
            read(mainfd, buf, length);
            write(*fd, buf, length);
          }

          int filterlength;
          read(mainfd, &filterlength, sizeof(int));
          write(*fd, &filterlength, sizeof(int));
          if (filterlength != 0)
          {
            char* filter = new char[filterlength];
            read(mainfd, filter, filterlength);
            write(*fd, filter, filterlength);
            delete[] filter;
          }

          for (int i = 0; i < argsnum; i++)
          {
            int arglength;
            read(mainfd, &arglength, sizeof(int));
            printf("arglength=%d\n", arglength);
            write(*fd, &arglength, sizeof(int));
            read(mainfd, buf, arglength);
            printf("buf=%s\n", buf);
            write(*fd, buf, arglength);
          }
          set<int>::iterator to_erase = fd;
          fd++;
          starvating_a.erase(to_erase);
        }
        else
        {
          fd++;
        }
      }

      for (set<int>::iterator fd = starvating_g.begin(); fd != starvating_g.end();)
      {
        write(mainfd, "g", 1);
        printf("sent get from %d to %d\n", *fd, mainfd);
        int length, startdepth;
        int res = read(mainfd, &length, sizeof(int));
        if (res == 0)
        {
          printf("job is done\n");
          shutdown(sfd, SHUT_RDWR);
          close(sfd);
          exit(0);
        }
        printf("length=%d\n", length);
        if (length > 0)
        {
          write(*fd, &length, sizeof(int));
          char* file = new char[length];
          int received = 0;
          while (received < length)
          {
            received += read(mainfd, file + received, length - received);
          }
          set<int>::iterator to_erase = fd;
          fd++;
          starvating_g.erase(to_erase);
        }
        else
        {
          fd++;
        }
      }
    }

    printf("selecting...\n");
    int res = select(max_d + 1, &readfds, NULL, NULL, NULL);
    printf("done\n");
    if (res < 1) 
    {

    }

    if (FD_ISSET(sfd, &readfds)) 
    {
      int cfd = accept(sfd, NULL, NULL);
      if (cfd < 0)
      {
        perror("error accept failed");
        close(sfd);
        exit(EXIT_FAILURE);
      }
      fds.push_back(cfd);
      printf("pushed back %d\n", cfd);
      //mainfd = cfd;
      //free++;
      printf("accepted\n");
    }

    printf("iterating through sockets...\n");
    for (vector<int>::iterator fd = fds.begin(); fd != fds.end(); fd++)
    {
      //printf("103\n");
      if (FD_ISSET(*fd, &readfds)) 
      {
        //printf("106\n");
        char command;
        int res = read(*fd, &command, 1);
        printf("res=%d command=%c\n", res, command);
        if ((res == 0) && (*fd == mainfd))
        {
          printf("job is done\n");
          close(sfd);
          exit(0);
        }
        if (command == 'm') 
        {
          printf("received m\n");
          mainfd = *fd;
          gameBegan = true;
        }
        else if (command == 'g')
        {
          printf("get from %d\n", *fd);
          printf("sending get to %d\n", mainfd);
          write(mainfd, "g", 1);

          int length, startdepth;
          read(mainfd, &length, sizeof(int));
          printf("length=%d\n", length);
          if (length > 0)
          {
            write(*fd, &length, sizeof(int));
            char* file = new char[length];
            int received = 0;
            while (received < length)
            {
              received += read(mainfd, file + received, length - received);
            }
            write(*fd, file, length);
            read(mainfd, &startdepth, sizeof(int));
            write(*fd, &startdepth, sizeof(int));
          }
          else
          {
            printf("added %d to starvated_g\n", *fd);
            starvating_g.insert(*fd);
          }          
        } 
        /*else if ((command == 'a') && gameBegan)
        {
          printf("all from %d\n", *fd);
          printf("sending all to %d\n", mainfd);
          write(mainfd, "a", 1);

          int namelength, length, startdepth, invertdepth, alarm, argsnum;
          bool useMemcheck, leaks, traceChildren, checkDanger;
          read(mainfd, &namelength, sizeof(int));
          printf("namelength=%d\n", namelength);
          if (namelength > 0)
          {
            write(*fd, &namelength, sizeof(int));
            char buf[128];
            read(mainfd, buf, namelength);
            printf("buf=%s\n", buf);
            write(*fd, buf, namelength);
            read(mainfd, &length, sizeof(int));
            write(*fd, &length, sizeof(int));
            char* file = new char[length];
            int received = 0;
            while (received < length)
            {
              received += read(mainfd, file + received, length - received);
            }
            write(*fd, file, length);
            read(mainfd, &startdepth, sizeof(int));
            write(*fd, &startdepth, sizeof(int));
            read(mainfd, &invertdepth, sizeof(int));
            write(*fd, &invertdepth, sizeof(int));
            read(mainfd, &alarm, sizeof(int));
            write(*fd, &alarm, sizeof(int));
            read(mainfd, &argsnum, sizeof(int));
            printf("argsnum=%d\n", argsnum);
            write(*fd, &argsnum, sizeof(int));

            read(mainfd, &useMemcheck, sizeof(bool));
            write(*fd, &useMemcheck, sizeof(bool));
            read(mainfd, &leaks, sizeof(bool));
            write(*fd, &leaks, sizeof(bool));
            read(mainfd, &traceChildren, sizeof(bool));
            write(*fd, &traceChildren, sizeof(bool));
            read(mainfd, &checkDanger, sizeof(bool));
            write(*fd, &checkDanger, sizeof(bool));

            for (int i = 0; i < argsnum; i++)
            {
              int arglength;
              read(mainfd, &arglength, sizeof(int));
              write(*fd, &arglength, sizeof(int));
              read(mainfd, buf, arglength);
              write(*fd, buf, arglength);
            }
          }
          else
          {
            printf("added %d to starvated_a\n", *fd);
            starvating_a.insert(*fd);
          }
        }*/
        else //game not began
        {
          printf("added %d to starvated_a\n", *fd);
          starvating_a.insert(*fd);
        }
      }
    }
  }
  return 0;
}

