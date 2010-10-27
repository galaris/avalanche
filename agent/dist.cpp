/* Server code in C */
 
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <algorithm>
#include <vector>
#include <set>

using namespace std;

vector<int> fds;
int sfd;
int mainfd = -1;

#define READ_MAIN(var, size) \
  if (read(mainfd, var, size) == -1) { \
    printf("connection with main avalanche is down\n"); \
    send_exit(); }

#define WRITE(fd, var, size) \
  if (write(fd, var, size) == -1) { \
    printf("connection with %d is down\n", fd); \
    fds.erase(find(fds.begin(), fds.end(), fd)); }


void send_exit()
{
  for (int i = 0; i < fds.size() && fds.at(i) != mainfd; i ++)
  {
    printf("sending exit to %d\n", fds.at(i));
    write(fds.at(i), "e", 1);
    close(fds.at(i));
  }
  close(mainfd);
  exit(0);
}

void sig_handler(int signo)
{
  shutdown(sfd, SHUT_RDWR);
  close(sfd);
  for (int i = 0; i < fds.size() && fds.at(i) != mainfd; i ++)
  {
    close(fds.at(i));
  }
  exit(0);
}
 
int main(int argc, char** argv)
{
  signal(SIGINT, sig_handler);
  signal(SIGPIPE, SIG_IGN);
  struct sockaddr_in stSockAddr;
  sfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

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

  set<int> starvating_a;
  set<int> starvating_g;

  bool gameBegan = false;

  int filenum ;
  bool sockets, datagrams;
 
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
        bool useMemcheck, leaks, traceChildren, checkDanger, debug, verbose, suppressSubcalls;
        char buf[128];
        READ_MAIN(buf, 1);
//first read 1 byte - either "r" or "q"
        if (*buf == 'q')
        {
          printf("main avalanche finished work\n");
          send_exit();
        }
        filenum = 0;
        READ_MAIN( &filenum, sizeof(int));
        printf("filenum=%d\n", filenum);
        if (filenum > 0)
        {
          WRITE(*fd, &filenum, sizeof(int));
          READ_MAIN( &sockets, sizeof(bool));
          WRITE(*fd, &sockets, sizeof(bool));
          READ_MAIN( &datagrams, sizeof(bool));
          WRITE(*fd, &datagrams, sizeof(bool));
          for (int j = 0; j < filenum; j ++)
          {
            if (!sockets && !datagrams)
            {
              READ_MAIN( &namelength, sizeof(int));
              printf("namelength=%d\n", namelength);
              WRITE(*fd, &namelength, sizeof(int));
              read(mainfd, buf, namelength);
              buf[namelength] = '\0';
              printf("buf=%s\n", buf);
              write(*fd, buf, namelength);
            }
            READ_MAIN( &length, sizeof(int));
            printf("length=%d\n", length);
            WRITE(*fd, &length, sizeof(int));
            char* file = new char[length];
            int received = 0;
            while (received < length)
            {
              int res = read(mainfd, file + received, length - received);
              if (res == -1)
              {
                printf("connection with main avalanche is down\n");
                send_exit();
              }
              received += res;
            }
            for (int j = 0; j < length; j++)
            {
              printf("%x", file[j]);
            }
            write(*fd, file, length);
            delete []file;
          }
          READ_MAIN( &startdepth, sizeof(int));
          WRITE(*fd, &startdepth, sizeof(int));
          READ_MAIN( &invertdepth, sizeof(int));
          WRITE(*fd, &invertdepth, sizeof(int));
          READ_MAIN( &alarm, sizeof(int));
          WRITE(*fd, &alarm, sizeof(int));
          READ_MAIN( &tracegrindAlarm, sizeof(int));
          printf("tracegrindAlarm=%d\n", tracegrindAlarm);
          WRITE(*fd, &tracegrindAlarm, sizeof(int));
          READ_MAIN( &threads, sizeof(int));
          WRITE(*fd, &threads, sizeof(int));
          READ_MAIN( &argsnum, sizeof(int));
          printf("argsnum=%d\n", argsnum);
          WRITE(*fd, &argsnum, sizeof(int));

          READ_MAIN( &useMemcheck, sizeof(bool));
          WRITE(*fd, &useMemcheck, sizeof(bool));
          READ_MAIN( &leaks, sizeof(bool));
          WRITE(*fd, &leaks, sizeof(bool));
          READ_MAIN( &traceChildren, sizeof(bool));
          WRITE(*fd, &traceChildren, sizeof(bool));
          READ_MAIN( &checkDanger, sizeof(bool));
          WRITE(*fd, &checkDanger, sizeof(bool));
          READ_MAIN( &debug, sizeof(bool));
          WRITE(*fd, &debug, sizeof(bool));
          READ_MAIN( &verbose, sizeof(bool));
          WRITE(*fd, &verbose, sizeof(bool));
          READ_MAIN( &suppressSubcalls, sizeof(bool));
          WRITE(*fd, &suppressSubcalls, sizeof(bool));

          if (sockets)
          {
            int length;
            READ_MAIN( &length, sizeof(int));
            WRITE(*fd, &length, sizeof(int));
            read(mainfd, buf, length);
            write(*fd, buf, length);
            int port;
            READ_MAIN( &port, sizeof(int));
            WRITE(*fd, &port, sizeof(int));
          }

          int masklength;
          READ_MAIN( &masklength, sizeof(int));
          WRITE(*fd, &masklength, sizeof(int));
          if (masklength != 0)
          {
            char* mask = new char[masklength];
            read(mainfd, mask, masklength);
            write(*fd, mask, masklength);
            delete[] mask;
          }

          int filtersNum;
          READ_MAIN( &filtersNum, sizeof(int));
          WRITE(*fd, &filtersNum, sizeof(int));
          for (int i = 0; i < filtersNum; i++)
          {
            int length; 
            READ_MAIN( &length, sizeof(int));
            WRITE(*fd, &length, sizeof(int));
            read(mainfd, buf, length);
            write(*fd, buf, length);
          }

          int filterlength;
          READ_MAIN( &filterlength, sizeof(int));
          WRITE(*fd, &filterlength, sizeof(int));
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
            READ_MAIN( &arglength, sizeof(int));
            printf("arglength=%d\n", arglength);
            WRITE(*fd, &arglength, sizeof(int));
            read(mainfd, buf, arglength);
            buf[arglength] = '\0';
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
        bool g_successful = false;
        int length, startdepth;
        char buf[2];
        READ_MAIN(buf, 1);
//first read 1 byte - either "r" or "q"
        if (*buf == 'q')
        {
          printf("main avalanche finished work\n");
          send_exit();
        }
        for (int j = 0; j < filenum; j ++)
        {
          READ_MAIN(&length, sizeof(int));
          if (length > 0)
          {
            WRITE(*fd, &length, sizeof(int));
            char* file = new char[length];
            int received = 0;
            while (received < length)
            {
              int res = read(mainfd, file + received, length - received);
              if (res == -1)
              {
                printf("connection with main avalanche is down\n");
                send_exit();
              }
              received += res;
            }
            g_successful = true;
            write(*fd, file, length);
            delete []file;
          }
          else break;      
        }
        if (g_successful)
        {
          READ_MAIN(&startdepth, sizeof(int));
          WRITE(*fd, &startdepth, sizeof(int));
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
    vector<int> to_erase;
    for (vector<int>::iterator fd = fds.begin(); fd != fds.end(); fd++)
    {
      //printf("103\n");
      if (FD_ISSET(*fd, &readfds)) 
      {
        //printf("106\n");
        char command;
        if (read(*fd, &command, 1) < 1)
        {
          if (*fd != mainfd)
          {
            printf("connection with %d is down\n", *fd);
            to_erase.push_back(*fd);
            continue;
          }
          else
          {
            send_exit();
          }
        }
        if (command == 'm') 
        {
          printf("received m\n");
          mainfd = *fd;
          gameBegan = true;
        }
        else if (command == 'q')
        {
          printf("main avalanche finished work\n");
          send_exit();
        }
        else if (command == 'g')
        {
          printf("added %d to starvated_g\n", *fd);
          starvating_g.insert(*fd);
        }         
        else //game not began
        {
          printf("added %d to starvated_a\n", *fd);
          starvating_a.insert(*fd);
        }
      }
    }
    for (vector<int>::iterator fd = to_erase.begin(); fd != to_erase.end(); fd ++)
    {
      fds.erase(find(fds.begin(), fds.end(), *fd));
      starvating_a.erase(*fd);
      starvating_g.erase(*fd);
    }
  }
  return 0;
}

