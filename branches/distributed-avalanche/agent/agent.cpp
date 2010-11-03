/* Server code in C */
 
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>

#define READ(var, type, sanity_check, print) \
    do \
    { \
      if (read(dist_fd, &var, sizeof(type)) <= 0) print_exit_error("connection with server is down"); \
      if (sanity_check && var < 0) print_exit_error("bad data"); \
      if (print) cout << #var "=" << var << endl; \
    } \
    while(0) 

#define PRINT_ARGS

using namespace std;

enum {HOST_POS = 1, PORT_POS = 2, REQUEST_NON_ZERO_POS = 3};

int dist_fd;
pid_t av_pid;
vector <string> file_name;
vector <string> av_arg;
int file_num;
char** avalanche_argv;
string exploit_info;

void print_exit_error(const char* msg)
{
  printf("%s\n", msg);
  close(dist_fd);
  file_name.clear();
  av_arg.clear();
  cout << "Exploits:" << endl << exploit_info << endl;
  exit(EXIT_FAILURE);
}

template <class T> string makeString(T data)
{
  ostringstream ss;
  ss << data;
  return ss.str();
}
 
template <class T> bool addArg(T arg, const char* arg_name)
{
  av_arg.push_back(string(arg_name) + makeString(arg));
  return true;
}

template <> bool addArg(bool trigger, const char* arg_name)
{
  if (trigger)
  {
    av_arg.push_back(string(arg_name));
  }
  return trigger;
}

bool addFileArg(const char* file_name, const char* arg_name)
{
  int file_length;
  READ(file_length, int, false, false);
  if (file_length != 0)
  {
    char* file = new char[file_length];
    if (read(dist_fd, file, file_length) < 0) 
    {
      delete []file;
      print_exit_error("connection with server is down");
    }
    int descr = open(file_name, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    if (descr == -1)
    {
      delete []file;
      print_exit_error("open failed");
    }
    write(descr, file, file_length);
    close(descr);
    delete[] file;
    av_arg.push_back(string(arg_name) + string(file_name));
    return true;
  }
  return false;
}

bool addStringArg(const char* arg_name)
{
  int string_length;
  READ(string_length, int, true, false);
  char* str = new char[string_length + 1];
  if (read(dist_fd, str, string_length) < 1)
  {
    delete []str;
    print_exit_error("connection with server is down");
  }
  str[string_length] = '\0';
  addArg(str, arg_name);
  delete []str;
  return true;
}

bool parseExploitLog()
{
  ifstream f("exploit_info.log");
  if (!(f.good()))
  {
    return false;
  }
  string line;
  int i = 0;
  while(!(f.eof()))
  {
    getline(f, line);
    exploit_info.append(line);
    if ((i ++) % 2)
    {
      exploit_info.append(string("\n"));
    }
  }
  f.close();
  return true;
}

void readInput(bool is_initial, bool is_network_app)
{
  int net_dist_fd, res, received, length = 0, namelength;
  if (is_network_app)
  {
    net_dist_fd = open("replace_data", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    write(net_dist_fd, &file_num, sizeof(int));
  }
  for (int i = 0; i < file_num; i ++)
  {
    if (!is_network_app && is_initial)
    {
      char *filename;
      READ(namelength, int, true, true);
      filename = new char[namelength + 1];
      received = 0;
      while (received < namelength)
      {
        res = read(dist_fd, filename + received, namelength - received);
        if (res < 1) print_exit_error("connection with server is down");
        received += res;
      }
      filename[namelength] = '\0';
      file_name.push_back(string(filename));
      delete []filename;
    }
    if (is_initial)
    {
      READ(length, int, true, true);
    }
    else
    {
      res = read(dist_fd, &length, sizeof(int));
      if (res == 1 && ((char)length) == 'e')
      {
        cout << "main avalanche finished work" << endl;
        av_arg.clear();
        file_name.clear();
        cout << "Exploits:" << endl << exploit_info << endl;
        exploit_info.clear();
        exit(0);
      }
    }
    char* file = new char[length];
    received = 0;
    while (received < length)
    {
      res = read(dist_fd, file + received, length - received);
      if (res < 1) 
      {
        delete []file;
        if (is_network_app) close(net_dist_fd);
        print_exit_error("connection with server is down");
      }
      received += res;
    }
    printf("\n");
    if (is_network_app)
    {
      write(net_dist_fd, &length, sizeof(int));
      write(net_dist_fd, file, length);
    }
    else
    {
      int descr = open(file_name.at(i).c_str(), O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
      if (descr == -1)
      {
        delete []file;
        print_exit_error("open failed");
      }
      write(descr, file, length);
      close(descr);
    }
    delete[] file;
  }
  if (is_network_app) close(net_dist_fd);
}

void sig_hndlr(int signo)
{
  if (signo == SIGUSR1)
  {
    write(dist_fd, "g", 1);
    int length, startdepth = 0;
    int descr = open("startdepth.log", O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
    for (int i = 0; i < file_num; i ++)
    {
      int res = read(dist_fd, &length, sizeof(int));
      if (res < 1)
      {
        write(descr, &startdepth, sizeof(int));
        close(descr);   
        kill(av_pid, SIGUSR2); 
        return;
      }
      if (length <= 0)
      {
        write(descr, &startdepth, sizeof(int));
        close(descr);   
        kill(av_pid, SIGUSR2); 
        print_exit_error("bad data");
      }
      char* file = new char[length];
      int received = 0;
      while (received < length)
      {
        int r = read(dist_fd, file + received, length - received);
        if (r < 1)
        {
          write(descr, &startdepth, sizeof(int));
          close(descr);
          delete []file;
          kill(av_pid, SIGUSR2);
          return;
        }
        received += r;
      }
      int dist_fdescr = open(file_name.at(i).c_str(), O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
      write(dist_fdescr, file, length);
      close(dist_fdescr);
      delete[] file;
    }
    read(dist_fd, &startdepth, sizeof(int));
    write(descr, &startdepth, sizeof(int));
    close(descr);
  
    kill(av_pid, SIGUSR2);
  }
  else if (signo == SIGINT)
  {
    av_arg.clear();
    file_name.clear();
    kill(av_pid, SIGINT);
    wait(NULL);
    parseExploitLog();
    cout << "Exploits:" << endl << exploit_info << endl;
    exploit_info.clear();
    if (avalanche_argv != NULL)
    {
      delete []avalanche_argv;
    }
    exit(0);
  }
}

void connectToServer(char* host, char* port)
{
  int res;
  struct sockaddr_in stSockAddr;
  memset(&stSockAddr, 0, sizeof(struct sockaddr_in));
 
  stSockAddr.sin_family = AF_INET;
  stSockAddr.sin_port = htons(atoi(port));
  res = inet_pton(AF_INET, host, &stSockAddr.sin_addr);
 
  if (res < 0)
  {
    perror("error: first parameter is not a valid address family");
    exit(EXIT_FAILURE);
  }
  else if (res == 0)
  {
    perror("char string (second parameter does not contain valid ipaddress)");
    exit(EXIT_FAILURE);
  }

  dist_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (dist_fd == -1)
  {
    perror("cannot create socket");
    exit(EXIT_FAILURE);
  }
    
  res = connect(dist_fd, (const struct sockaddr*)&stSockAddr, sizeof(struct sockaddr_in));
 
  if (res < 0)
  {
    perror("error connect failed");
    close(dist_fd);
    exit(EXIT_FAILURE);
  }  

  printf("connected\n");
}
  
int main(int argc, char** argv)
{
  if (argc < HOST_POS + 1)
  {
    printf("invalid args\nusage: av-agent host port\n");
    exit(EXIT_FAILURE);
  }
  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, sig_hndlr);
  int res;
  bool requestNonZero = false;
  if ((argc == REQUEST_NON_ZERO_POS + 1) && !strcmp(argv[REQUEST_NON_ZERO_POS], "--request-non-zero"))
  {
    requestNonZero = true;
  }
  connectToServer(argv[HOST_POS], argv[PORT_POS]);
  
  if (write(dist_fd, "a", 1) < 1) print_exit_error("connection with server is down");
  int namelength, length, startdepth, invertdepth, alarm, tracegrindAlarm, threads, argsnum;
  bool useMemcheck, leaks, traceChildren, checkDanger, debug, verbose, sockets, datagrams, suppressSubcalls, STPThreadsAuto;
  int received, net_dist_fd;
  unsigned int st_depth_pos, branch_pos;
  
  READ(file_num, int, true, true);
  READ(sockets, bool, false, true);
  READ(datagrams, bool, false, true);

  readInput(true, sockets || datagrams);  

  READ(startdepth, int, true, true);
  READ(invertdepth, int, true, true);
  READ(alarm, int, true, true);
  READ(tracegrindAlarm, int, true, true);
  READ(threads, int, true, true);
  READ(argsnum, int, true, true);
  READ(useMemcheck, bool, false, true);
  READ(leaks, bool, false, true);
  READ(traceChildren, bool, false, true);
  READ(checkDanger, bool, false, true);
  READ(debug, bool, false, true);
  READ(verbose, bool, false, true);
  READ(suppressSubcalls, bool, false, true);
  READ(STPThreadsAuto, bool, false, true);
 
  size_t sl = string(argv[0]).find_last_of('/');
  if (sl != string::npos) 
  {
    av_arg.push_back(string(argv[0]).substr(0, sl + 1) + string("avalanche"));
  }
  else
  {
    av_arg.push_back(string("avalanche"));
  }
  if (!sockets && !datagrams)
  {
    for (int i = 0; i < file_num; i ++)
    {
      addArg(file_name[i], "--filename=");
    }
  }

  addArg(invertdepth, "--depth=");
  st_depth_pos = av_arg.size();
  addArg(startdepth, "--startdepth=");
  addArg(alarm, "--alarm=");
  branch_pos = av_arg.size();
  av_arg.push_back(string("--prefix=branch0_"));

  if (!addArg(STPThreadsAuto, "--stp-threads-auto"))
  {
    if (threads != 0)
    {
      addArg(threads, "--stp-threads=");
    }
  }

  addArg(requestNonZero, "--agent");

  int runs = 0;
  if (tracegrindAlarm != 0) addArg(tracegrindAlarm, "--tracegrind-alarm=");
  addArg(useMemcheck, "--use-memcheck");
  addArg(leaks, "--leaks");
  addArg(traceChildren, "--trace-children");
  addArg(checkDanger, "--check-danger");
  addArg(debug, "--debug");
  addArg(verbose, "--verbose");
  addArg(sockets, "--sockets");
  addArg(datagrams, "--datagrams");
  addArg(suppressSubcalls, "--suppress-subcalls");
  addArg(true, "--log-exploit-info");

  if (sockets)
  {
    addStringArg("--host=");
    int port;
    READ(port, int, true, true);
    addArg(port, "--port=");
  }

  addFileArg("mask", "--mask=");  

  int filtersNum;
  READ(filtersNum, int, false, true);
  for (int i = 0; i < filtersNum; i++)
  {
    addStringArg("--func-name=");
  }  

  addFileArg("filter", "--filter=");
 
  for (int i = 0; i < argsnum; i++)
  {
    addStringArg("");
  }

#ifdef PRINT_ARGS
  for (int i = 0; i < av_arg.size(); i ++)
  {
    cout << "arg[" << i << "]=" << av_arg[i] << endl;
  }
#endif

  for (;;)
  {
    signal(SIGUSR1, sig_hndlr);
    avalanche_argv = new char*[av_arg.size() + 1];
    for (int i = 0; i < av_arg.size(); i ++)
    {
      avalanche_argv[i] = (char*) av_arg[i].c_str();
    }
    avalanche_argv[av_arg.size()] = NULL;
    av_pid = fork();
    if (av_pid == 0)
    {
      printf("starting child avalanche...\n");
      execvp(avalanche_argv[0], avalanche_argv);
    }
    wait(NULL);
    delete []avalanche_argv;
    parseExploitLog();
    avalanche_argv = NULL;

    write(dist_fd, "g", 1);
    int length, startdepth;

    readInput(false, sockets || datagrams);

    READ(startdepth, int, true, true);
    av_arg[st_depth_pos] = string("--startdepth=") + makeString(startdepth);
    av_arg[branch_pos] = string("--prefix=branch") + makeString(++runs) + string("_");
#ifdef PRINT_ARGS
    cout << "arg[" << st_depth_pos << "]=" << av_arg[st_depth_pos] << endl;
    cout << "arg[" << branch_pos << "]=" << av_arg[branch_pos] << endl;
#endif
  }
  close(dist_fd);
  cout << "Exploits:" << endl << exploit_info << endl;
  return 0;
}

