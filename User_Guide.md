

# Installation #
### Getting the sources ###
#### From source archive ####

Download and unpack the source archive from [the list of available downloads](http://code.google.com/p/avalanche/downloads/list)
```
$ tar xf avalanche-VERSION.tar.gz
$ cd avalanche-VERSION
```

#### From subversion repository ####

Checkout the sources:
```
$ svn checkout http://avalanche.googlecode.com/svn/trunk avalanche
$ cd avalanche
```

### Configuring and building ###

If you did the checkout from subversion repository, run autogen script
```
$ ./autogen.sh
```

Run configure and make
```
$ ./configure --prefix=<path to avalanche install directory>
$ make
$ make install
```

If you want to use Avalanche for **Android**, please refer to README.android file in distribution for specific installation instructions.

# Basic usage #
To perform analysis using Avalanche you will need the following:
  * Program executable (built for your machine architecture)
  * One or several input files (if the program reads data from files)
  * IP and port number (if the program reads data from socket)
You should also consider the fact that Valgrind and therefore Avalanche works more efficiently if the executable was built with debug info and with optimization turned off. You may want to rebuild your program with the appropriate options before using Avalanche.

We will be using sample programs that are included in distribution and built along with Avalanche. We also use /path\_to\_avalanche/inst as install directory.
## File input ##
There are a number of points concerning using files as a source of input you may want to consider before using Avalanche.
  1. There is no common rule what data input files should contain in order to maximize analysis efficiency. Basically, however, you can using files in correct format for the program and/or files with garbage data.
  1. Avalanche cannot construct input files which are bigger than initial. Therefore, a number of paths can be unchecked if the supplied initial files are too small.
  1. For most programs supplying very big input files will lead to substantial increase in amount of time required for analysis.

The following is sample Avalanche run on one of supplied in distribution test examples (entry.c)

```
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int* i;

int main(int argc, char** argv)
{
  int  j = 0;
  char local[3];
  int  fd1 = open(argv[1], O_RDONLY | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);

  read(fd1, local, 3);
  if (local[0] < 5) { //1
      j++;
  }
  if (local[1] < 3) { //2
      j++;
  }
  if (j == 2) {
      i = (int*) malloc(sizeof(int));
  }
  *i = 2;
  return 0;
}
```

This program reads 4 bytes from a file supplied as a command line argument. If conditions 1 and 2 are satisfied pointer _i_ is initialized with allocated memory. If one of conditions is not satisfied, _i_ stays a NULL-pointer, triggering a segmentation fault upon dereferencing.

Now, we will be using a correct file (not causing segmentation fault) as initial input (an example of such file is also included in distribution and is used for almost all sample programs) and run Avalanche:
```
$ ./inst/bin/avalanche --filename=samples/simple/seed ./samples/simple/entry samples/simple/seed
```

'--filename' option specifies the name of the file we want to use as a source of input data.

'./samples/simple/entry samples/simple/seed' is the program and its arguments (single filename in this example).

Avalanche performs 4 iterations with the following output:
```
Iteration 1. Tue Dec 27 17:44:12 2011
  Received SIGSEGV
  Command:  ./samples/simple/entry exploit_0_0

  Received SIGSEGV
  Command:  ./samples/simple/entry exploit_1_0

Iteration 2. Tue Dec 27 17:44:14 2011
  Received SIGSEGV
  Command:  ./samples/simple/entry exploit_2_0

Iteration 3. Tue Dec 27 17:44:15 2011
Iteration 4. Tue Dec 27 17:44:15 2011
Unique error(s) found: 1.

 Error #0: Received SIGSEGV
  Inputs:   exploit_0_0; exploit_1_0; exploit_2_0; 
  Command:  ./samples/simple/entry exploit_0_0


Time statistics: 4 sec, tracegrind: 2 (50 %), covgrind: 2 (50 %), stp: 0 (0 %).
```

The analysis has finished and 3 input files that cause segmentation fault (program received SIGSEGV) were generated. We can check discovered exploits with gdb:
```
$ gdb --args ./samples/simple/entry exploit_0_0
GNU gdb 6.8-debian
Copyright (C) 2008 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i486-linux-gnu"...
(gdb) r
Starting program: <...>/avalanche-trunk/samples/simple/entry exploit_0_0

Program received signal SIGSEGV, Segmentation fault.
0x0804845d in main (argc=-536870880, argv=0x38bfa3a3) at entry.c:26
26	  *i = 2;
(gdb) p i
$1 = (int *) 0x0
```

Checking exploit\_0\_0 with hexdump utility shows the following:
```
$ hexdump exploit_0_0
0000000 0020 0000                              
0000004
```
Using exploit\_0\_0 for our test program causes condition 1 not to be satisfied triggering segmentation fault. Other 2 exploit files correspond to situations where condition 2 is not satisfied and where both conditions are not satisfied.
Avalanche also creates error\_list.log file with the following contents:
```
Error 0
Process terminating with default action of signal 11 (SIGSEGV)
 Access not within mapped region at address 0x0
   at 0x804845D: main (entry.c:26)
 ./samples/simple/entry exploit_0_0
 ./samples/simple/entry exploit_1_0
 ./samples/simple/entry exploit_2_0
```
The contents consist of information about discovered errors (stacktrace) and commands to reproduce these errors.
## Socket input ##
Avalanche also supports programs that get input data in form of messages from sockets. Without additional preparations Avalanche can only be used for client programs that get data from real working servers. IP and port number of connection that is being established is also required.

For demonstration we will use one of test cases in Avalanche distribution. We will also use a simple server that supplies data for tested program (sending 4-byte messages with zero values).

First, we need to start the server application:
```
$ ./samples/simple/writeserver &
[1] 7831
```
Server is started in background mode and needs to be killed later.

Then we run Avalanche on one of our test programs - multiple\_client.
This program connects to local server on 10000 port and receives 4 bytes. If the message forms string 'bad!', program calls abort().
```
$ ./inst/bin/avalanche --sockets --host=127.0.0.1 --port=10000 samples/simple/multiple_client
```
'--sockets' option specifies that socket interaction should be tracked. '--host' and '--port' options specify connection that will be established and needs to be tracked.

Avalanche work for several iterations and generates exploit\_0 and error\_list.log files and produces the following output:
```
Iteration 1. Tue Dec 27 18:07:12 2011
Iteration 2. Tue Dec 27 18:07:14 2011
Iteration 3. Tue Dec 27 18:07:15 2011
Iteration 4. Tue Dec 27 18:07:17 2011
Iteration 5. Tue Dec 27 18:07:18 2011
Iteration 6. Tue Dec 27 18:07:19 2011
Iteration 7. Tue Dec 27 18:07:20 2011
  Received SIGABRT
  Command:  ./inst/bin/../lib/avalanche/valgrind --tool=covgrind --host=127.0.0.1 --port=10000 --replace=exploit_0 --sockets=yes samples/simple/multiple_client

Iteration 8. Tue Dec 27 18:07:22 2011
Iteration 9. Tue Dec 27 18:07:23 2011
Iteration 10. Tue Dec 27 18:07:24 2011
Iteration 11. Tue Dec 27 18:07:25 2011
Iteration 12. Tue Dec 27 18:07:26 2011
Iteration 13. Tue Dec 27 18:07:27 2011
Iteration 14. Tue Dec 27 18:07:28 2011
Iteration 15. Tue Dec 27 18:07:29 2011
Iteration 16. Tue Dec 27 18:07:30 2011
Unique error(s) found: 1.

 Error #0: Received SIGABRT
  
  Command:  ./inst/bin/../lib/avalanche/valgrind --tool=covgrind --host=127.0.0.1 --port=10000 --replace=exploit_0 --sockets=yes samples/simple/multiple_client


Time statistics: 19 sec, tracegrind: 15 (78.9474 %), covgrind: 4 (21.0526 %), stp: 0 (0 %).
```
The command in the ending report can be used to reproduce the error:
```
./inst/bin/../lib/avalanche/valgrind --tool=covgrind --host=127.0.0.1 --port=10000 --replace=exploit_0 --sockets=yes samples/simple/multiple_client
==14107== Covgrind-1.0, IR basic blocks addresses dumper
==14107== Copyright (C) iisaev
==14107== Using Valgrind-3.7.0.SVN and LibVEX; rerun with -h for copyright info
==14107== Command: samples/simple/multiple_client
==14107== 
==14107== 
Aborted
```
Basically, exploit\_0 holds the message that will cause SIGABRT if it is received from the server. We cannot modify what server sends and thus need to intercept it and replace it - that is precisely what covgrind plugin for valgrind can do.
In the end we will kill our server application.
```
$ kill 7831
```
# Advanced features #
## Customizing points of interest ##
Avalanche provides several ways to perform more specific checks of the program. Firstly, these include specifying what areas of program we need to analyze. Secondly, Avalanche allows to use different valgrind plugins (memcheck and helgrind) to detect non-fatal errors.
### Function filtering ###
Normally, Avalanche performs complete analysis of the program. However, we can narrow down the analysis specifying only a limited number of functions we want to analyze.

We will use one of example programs supplied with Avalanche (separate\_analysis\_sample.c)

```
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int i = 0;
int exploit_i = 0;
int* d;

void f1(char value)
{
  if (value < 1)
  {
    i++;
  }
}

void f2(char value)
{
  if (value < 2)
  {
    i++;
  }
}

void f3(char value)
{
  if (value < 5)
  {
    i++;
  }
}

void f4(char value)
{
  if (value < 13)
  {
    exploit_i++;
  }
}

int main(int argc, char** argv)
{
  int j, fd1 = open(argv[1], O_RDONLY | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
  char input[4];
  read(fd1, input, 4);
  f1(input[0]);
  f2(input[1]);
  f3(input[2]);
  f4(input[3]);
  if (exploit_i)
  {
    d = (int*) malloc(sizeof(int));
  }
  *d = 1;
  return 0;
}
```

This program is similar to our first example (entry.c). However, there are now 4 conditions, each operation on corresponding byte of input file and only the last byte and function _f4_ can cause segmentation fault.

In order to find this error much faster, we will specify that we want Avalanche to check only function _f4_. This can be done by either '--func-name' option or '--func-file' option. The latter is more useful when there are several functions we want to check. We will run Avalanche with the first option and use the same initial file we used to entry.c:
```
$ ./inst/bin/avalanche --func-name=f4 --filename=samples/simple/seed  samples/simple/separate_analysis_sample samples/simple/seed
```

Avalanche detects the error on the first iteration:
```
Iteration 1. Tue Dec 27 18:37:23 2011
  Received SIGSEGV
  Command:  samples/simple/separate_analysis_sample exploit_0_0

Iteration 2. Tue Dec 27 18:37:24 2011
Unique error(s) found: 1.

 Error #0: Received SIGSEGV
  Inputs:   exploit_0_0; 
  Command:  samples/simple/separate_analysis_sample exploit_0_0


Time statistics: 3 sec, tracegrind: 2 (66.6667 %), covgrind: 1 (33.3333 %), stp: 0 (0 %).
```

Function filtering can be used effectively in several cases but generally does not provide flexible capabilities - in complex applications data dependencies span across multiple functions and need to be checked as a whole in order to perform reasonable analysis.
### Input masks ###
Another feature provided by Avalanche allows to map different parts of input files or socket messages in order to analyse the influence of specified segments of data.
To use this feature we must provide a mask file. To demonstrate input mapping capabilities we will use the previous example, separate\_analysis\_sample.c. This time, we will not specify '--func-name' option but add '--mask=mask1'.
File mask1 contains the following value:
```
0x3
```
Using this mask with Avalanche will result in checking only the influence of the last (4th) byte in input file. As this byte actually can cause segmentation fault, Avalanche will be able to detect the error.

```
$ ./inst/bin/avalanche --mask=mask1 --filename=samples/simple/seed samples/simple/separate_analysis_sample samples/simple/seed
Iteration 1. Tue Dec 27 18:53:16 2011
  Received SIGSEGV
  Command:  samples/simple/separate_analysis_sample exploit_0_0

Iteration 2. Tue Dec 27 18:53:17 2011
Unique error(s) found: 1.

 Error #0: Received SIGSEGV
  Inputs:   exploit_0_0; 
  Command:  samples/simple/separate_analysis_sample exploit_0_0


Time statistics: 2 sec, tracegrind: 2 (100 %), covgrind: 0 (0 %), stp: 0 (0 %).
```
The point of using mask files is (as with function filtering) to reduce the scope of analysis thus reducing the amount of time required to perform the analysis.
Mask files support individual offsets (like 0x3 in the example) as well as offset ranges (e.g. 0x23-0x4c). Multiple lines in mask map corresponding input files.
### Detecting non-fatal errors ###
Avalanche supports memcheck and helgrind plugins for detecting memory and concurrency errors accordingly. Specifying '--tool=plugin\_name' option will allow to detect necessary type of errors. The following points should be taken into account:
  1. If memcheck is used, all generated error files will be named 'memcheck\_x\_y' instead of 'exploit\_x\_y'. If helgrind is used, all generated error files will be named 'concurrency\_x\_y' instead of 'exploit\_x\_y'
  1. helgrind is not available for Android builds of Avalanche
## Customizing analysis process ##
Avalanche provides addition features for increasing the speed of analysis using parallelization and distributed runs.
### STP Multi-threading ###
Avalanche can be configured to run its STP component in parallel using pthreads with either '--stp-threads=auto' or '--stp-threads=N' option. 'Auto' option will cause Avalanche to select optimal number of threads to run STP, while '--stp-threads=N' option can be used to specify custom number of threads.
### Distributed runs ###
Avalanche can be run on multiple machines in a network using socket mechanism.
In order to do so, several steps should be taken:
  1. Avalanche job manager is started on one of the machines:
```
$ ./inst/bin/av-dist port_number
```
  1. Main instance of Avalanche is started on one of the machines (typically the same as in the previous step):
```
./inst/bin/avalanche --distributed --dist-host=host_IP --dist-port=port_number program program_arguments
```
> > Here host\_IP is IP address of job manager machine and port\_number is the same as for the job manager.
  1. Then Avalanche job agents are started on other machines:
```
$ ./inst/bin/av-agent host_IP port_number
```
> > Here host\_IP is IP address of job manager machine and port\_number is the same as for the job manager.

Each job agent will receive inputs from main instance of Avalanche and will use this inputs as initial. All exploits detected are stored on job agent machines, but will be labelled with different prefixes.

The following principle should be taken into account while using distributed runs: as program name and its arguments are specified once for main instance of Avalanche, they should be consistent with all job agent machines. Mainly, this concerns the paths to program and its arguments.

The path issue can be demonstrated with this example:
Main instance of Avalanche is started with the following options:
```
./inst/bin/avalanche --distributed --dist-host=127.0.0.1 --dist-port=10000 --filename=seed /home/user1/prog1/prog seed
```
All job agents machines should have prog installed in /home/user1/prog1 directory. Also, initial input files are copied from main instance machine to job agent machines and should be consistent with directory structure for each job agent machine.
### Split-mode ###
Avalanche also allows to perform tested program runs on one machine while all other processing (STP) is executed on another machine. This is mainly used for testing ARM devices due to their lower processing capabilities.
Connection between two machines is established using sockets mechanism. Two different ways to establish the connection are available: either the host machine (where STP is executed) connects to target machine (where program runs are performed) and vice versa. The first variant is mainly used for Android platform with Android Data Bridge. For all other purposes we suggest using the second variant as it is more appropriate in terms of host-client architecture.
The following examples show the usage of both variants:

Target connects to host:
  1. On host (e.g. x86):
```
$ ./inst/bin/avalanche --filename=seed --remote-valgrind=client --remote-port=port_number samples/simple/entry seed
```
  1. On target (e.g. ARM):
```
$ ./inst/bin/plugin-agent --port=port_number --host=host_IP
```

Host connect to target:

  1. On target (e.g. ARM):
```
$ bin/plugin-agent --port=port_number
```
  1. On host (e.g. x86):
```
$ ./inst/bin/avalanche --filename=seed --remote-valgrind=host --remote-host=host_IP --remote-port=port_number samples/simple/entry seed
```

The path issue is also important for split-mode runs. For both variants of split-mode the path to executable (/samples/simple/entry in example) is the path on **target device**. Initial input files are copied from host machine to target machine according to their paths specified in run command and therefore should be consistent with target device directory structure.
# Customizing output #
There are a number of options provided by Avalanche to customize analysis output.
  1. '--verbose' and '--debug' options can be used to include more information in Avalanche output
  1. '--result-dir=directory\_name' option allows to specify a directory where exploit files and error\_list.log will be stored
  1. '--prefix=prefix' option allows to specify a prefix that will be appended to all exploit files