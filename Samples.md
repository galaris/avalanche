## Usage Examples ##

Avalanche comes with some simple examples. Their sources are located in
[samples/simple](http://code.google.com/p/avalanche/source/browse/trunk/samples/simple/) folder. It also contains [seed](http://code.google.com/p/avalanche/source/browse/trunk/samples/simple/seed) file - it is initial input file for the examples. It contains just four zero bytes.

```
user@machine:$ hexdump samples/simple/seed 
0000000 0000 0000                              
0000004
```

## If input data comes from file ##

For programs that receive their input data from files just specify the name of the file with '--filename' option. [sample2.c](http://code.google.com/p/avalanche/source/browse/trunk/samples/simple/sample2.c) is a small program that terminates if and only if it reads the letters 'b', 'a', 'd', '!' from input file. This is how avalanche may be used to detect the crash and generate input file that reproduces it.

```
user@machine:$ ./inst/bin/avalanche --filename=samples/simple/seed samples/simple/sample2 samples/simple/seed 
```

Avalanche generates exploit file exploit\_0\_0

```
user@machine:$ cat exploit_0_0 
bad!
```

Check that file causes the sample program to crash:

```
user@machine:$ samples/simple/sample2 exploit_0_0 
Aborted
```

### If input data comes from TCP socket ###

For programs that receive their input data from TCP sockets provide host and port of server with '--host' and '--port' options. You should also specify '--sockets' option. Analysis also requires the server to be running.

[writeserver.c](http://code.google.com/p/avalanche/source/browse/trunk/samples/simple/writeserver.c) - is a simple server for [multiple\_client.c](http://code.google.com/p/avalanche/source/browse/trunk/samples/simple/multiple_client.c), [multiple\_client2.c](http://code.google.com/p/avalanche/source/browse/trunk/samples/simple/multiple_client2.c) and [divclient.c](http://code.google.com/p/avalanche/source/browse/trunk/samples/simple/divclient.c) samples. It accepts any incoming connection, writes four bytes into it and closes the connection.

So, run the server first:

```
user@machine:$ samples/simple/writeserver &
[1] 7831
```

Then start the analysis:

```
user@machine:$ ./inst/bin/avalanche --sockets --host=127.0.0.1 --port=10000 samples/simple/multiple_client
```

Avalanche generates exploit\_0 file. To reproduce the actual crash, use covgrind plugin:

```
user@machine:$ ./inst/bin/valgrind --tool=covgrind --host=127.0.0.1 --port=10000 --replace=exploit_0 --sockets=yes samples/simple/multiple_client
==7911== Covgrind-1.0, IR basic blocks addresses dumper.
==7911== Copyright (C) iisaev
==7911== Using LibVEX rev 3, a library for dynamic binary translation.
==7911== Copyright (C) 2004-2008, and GNU GPL'd, by OpenWorks LLP.
==7911== Using valgrind-3.5.0.SVN, a dynamic binary instrumentation framework.
==7911== Copyright (C) 2000-2008, and GNU GPL'd, by Julian Seward et al.
==7911== For more details, rerun with: -v
==7911== 
caught connect arg0=3 arg1=beea078c arg2=10
caught connect arg0=4 arg1=beea078c arg2=10
caught connect arg0=5 arg1=beea078c arg2=10
caught connect arg0=6 arg1=beea078c arg2=10
caught read from socket, cursocket=0 curoffs=0
caught read from socket, cursocket=1 curoffs=0
caught read from socket, cursocket=2 curoffs=0
caught read from socket, cursocket=3 curoffs=0
==7911== 
Aborted
```

### To detect an error that doesn't cause a crash ###

Use '--use-memcheck' option. This will cause Avalanche to use memcheck instead of covgrind, which slows down the analysis, but allows non-critical bugs to be detected. [mleak.c](http://code.google.com/p/avalanche/source/browse/trunk/samples/simple/mleak.c) sample introduces the simplest memory leak defect. Run the Avalanche as follows:

```
user@machine:$ ./inst/bin/avalanche --use-memcheck --leaks --filename=samples/simple/seed samples/simple/mleak samples/simple/seed 
```

Avalanche generates memcheck\_0\_0 file. To reproduce the bug, run the memcheck plugin:

```
user@machine:$ ./inst/bin/valgrind --tool=memcheck samples/simple/mleak memcheck_0_0 
==8371== Memcheck, a memory error detector.
==8371== Copyright (C) 2002-2008, and GNU GPL'd, by Julian Seward et al.
==8371== Using LibVEX rev 3, a library for dynamic binary translation.
==8371== Copyright (C) 2004-2008, and GNU GPL'd, by OpenWorks LLP.
==8371== Using valgrind-3.5.0.SVN, a dynamic binary instrumentation framework.
==8371== Copyright (C) 2000-2008, and GNU GPL'd, by Julian Seward et al.
==8371== For more details, rerun with: -v
==8371== 
==8371== 
==8371== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 16 from 1)
==8371== malloc/free: in use at exit: 4 bytes in 1 blocks.
==8371== malloc/free: 1 allocs, 0 frees, 4 bytes allocated.
==8371== For counts of detected errors, rerun with: -v
==8371== searching for pointers to 1 not-freed blocks.
==8371== checked 51,420 bytes.
==8371== 
==8371== LEAK SUMMARY:
==8371==    definitely lost: 4 bytes in 1 blocks.
==8371==      possibly lost: 0 bytes in 0 blocks.
==8371==    still reachable: 0 bytes in 0 blocks.
==8371==         suppressed: 0 bytes in 0 blocks.
==8371== Rerun with --leak-check=full to see details of leaked memory.
```

## Input masks and function filtering ##

See a separate wiki page describing these features: [Input\_masks\_and\_function\_filtering](Input_masks_and_function_filtering.md)

## Distributed analysis and multiple threads for STP queries ##

See a separate wiki page describing these features: [Distributed\_avalanche](Distributed_avalanche.md)