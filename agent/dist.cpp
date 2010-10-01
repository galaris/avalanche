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
  inet_pton(AF_INET, "127.0.0.1", &stSockAddr.sin_addr);

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

  int free = -1;
  int mainfd;
  set<int> starvating;
 
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
    printf("selecting...\n");
    int res = select(max_d + 1, &readfds, NULL, NULL, NULL);
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
      mainfd = cfd;
      free++;
      printf("accepted\n");
    }

    for (set<int>::iterator fd = starvating.begin(); fd != starvating.end();)
    {
      write(mainfd, "g", 1);

      int length, startdepth, invertdepth, alarm;
      bool useMemcheck, leaks, traceChildren, checkDanger;
      read(mainfd, &length, sizeof(int));
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
        read(mainfd, &invertdepth, sizeof(int));
        write(*fd, &invertdepth, sizeof(int));
        read(mainfd, &alarm, sizeof(int));
        write(*fd, &alarm, sizeof(int));
        read(mainfd, &useMemcheck, sizeof(bool));
        write(*fd, &useMemcheck, sizeof(int));
        read(mainfd, &leaks, sizeof(bool));
        write(*fd, &leaks, sizeof(int));
        read(mainfd, &traceChildren, sizeof(bool));
        write(*fd, &traceChildren, sizeof(bool));
        read(mainfd, &checkDanger, sizeof(bool));
        write(*fd, &checkDanger, sizeof(bool));
        set<int>::iterator to_erase = fd;
        fd++;
        starvating.erase(to_erase);
      }
      else
      {
        fd++;
      }
    }

    printf("iterating through sockets...\n");
    for (vector<int>::iterator fd = fds.begin(); fd != fds.end(); fd++)
    {
      //printf("103\n");
      if (FD_ISSET(*fd, &readfds)) 
      {
        //printf("106\n");
        char command;
        read(*fd, &command, 1);
        if (command == 'g') //get
        {
          printf("get from %d\n", *fd);
          printf("sending get to %d\n", mainfd);
          write(mainfd, "g", 1);

          int length, startdepth, invertdepth, alarm;
          bool useMemcheck, leaks, traceChildren, checkDanger;
          read(mainfd, &length, sizeof(int));
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
            read(mainfd, &invertdepth, sizeof(int));
            write(*fd, &invertdepth, sizeof(int));
            read(mainfd, &alarm, sizeof(int));
            write(*fd, &alarm, sizeof(int));
            read(mainfd, &useMemcheck, sizeof(bool));
            write(*fd, &useMemcheck, sizeof(int));
            read(mainfd, &leaks, sizeof(bool));
            write(*fd, &leaks, sizeof(int));
            read(mainfd, &traceChildren, sizeof(bool));
            write(*fd, &traceChildren, sizeof(bool));
            read(mainfd, &checkDanger, sizeof(bool));
            write(*fd, &checkDanger, sizeof(bool));
          }
          else
          {
            starvating.insert(*fd);
          }
        }
      }
    }
  }
  return 0;
}

