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
  int mainfd;
  set<int> starvating;

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
      for (set<int>::iterator fd = starvating.begin(); fd != starvating.end();)
      {
        write(mainfd, "g", 1);
        printf("sent get from %d to %d\n", *fd, mainfd);
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
          set<int>::iterator to_erase = fd;
          fd++;
          starvating.erase(to_erase);
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
      if (*fd == mainfd)
      {
        continue;
      }
      //printf("103\n");
      if (FD_ISSET(*fd, &readfds)) 
      {
        //printf("106\n");
        char command;
        read(*fd, &command, 1);
        if (command == 'm') 
        {
          printf("received m\n");
          mainfd = *fd;
          gameBegan = true;
        }
        else if ((command == 'g') && gameBegan)
        {
          printf("get from %d\n", *fd);
          printf("sending get to %d\n", mainfd);
          write(mainfd, "g", 1);

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
            printf("added %d to starvated\n", *fd);
            starvating.insert(*fd);
          }
        }
        else //game not began
        {
          printf("added %d to starvated\n", *fd);
          starvating.insert(*fd);
        }
      }
    }
  }
  return 0;
}

