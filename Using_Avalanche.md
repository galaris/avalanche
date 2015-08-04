### Using Avalanche ###

### Synopsis ###
avalanche _avalanche-options_ _program_ _program-options_

This command will iteratively run the _program_ with specified command line _program-options_ under Avalanche. The program's executable (binary) code will be dynamically instrumented and analysed by Avalanche to detect errors, and generate inputs for the next iteration.

### Avalanche options ###

| **flag name** | **default** | **description** |
|:--------------|:------------|:----------------|
| **Avalanche general options** |             |                 |
|--help         |             |Print help and exit|
|--verbose      |             |Much more detailed avalanche output|
|--debug        |             |Save some debugging information - divergent inputs, etc.|
|--check-danger |             |Emit special constraints for memory access operations and divisions|
|--trace-children|             |Run valgrind plugins with '--trace-children=yes' option|
| --depth=number |100          |The number of conditions collected during one run of tracegrind. May be used in the form '--depth=infinity', which means that tracegrind should collect all conditions in the trace|
|--use-memcheck |             |Indicate that memcheck should be used instead of covgrind|
|--leaks        |             |Indicate that inputs resulting in memory leaks should be saved (ignored if '--use-memcheck' isn't specified)|
| --stp-threads=number |             |The number of STP queries handled simultaneously. May be used in the form '--stp-threads=auto'. In this case the number of CPU cores is taken.|
| --report-log=filename |             |Dump exploits report to the specified file.|
| **if the program receives input data from files** |             |                 |
| --filename=input\_file |             |The path to the file with the input data for the analyzed program (may be used multiple times)|
| --alarm=number |300          |Timer value in seconds (for infinite loop recognition). If the execution runs for the specified number of seconds, then Avalanche suspects an infinite loop in the program and dumps the corresponding input file as exploit|
| **if the program receives input data from sockets** |             |                 |
|--sockets      |             |Mark data read from TCP sockets as tainted|
|--datagrams    |             |Mark data read from UDP sockets as tainted|
| --host=IPv4\_address |not set      |IP address of the network connection (for TCP sockets only)|
| --port=number |not set      |Port number of the network connection (for TCP sockets only)|
| --alarm=number |not set      |Timer for breaking infinite waitings in covgrind or memcheck. It designates the maximum time for each run of covgrind or memcheck. If the timer expires, the plugin is killed. Set this option if the analysed program "hangs" on some iteration.|
| --tracegrind-alarm=number |not set      |Timer for breaking infinite waitings in tracegrind. It designates the maximum time for each run of tracegrind. If the timer expires, the plugin is killed. Set this option if the analysed program "hangs" on some iteration. In general, this value should be greater than the timer for covgrind or memcheck specified by '--alarm' option.|
| **[masks and separate function analysis](http://code.google.com/p/avalanche/wiki/Input_masks_and_function_filtering)** |             |                 |
| --mask=mask\_file |             |The path to the [mask file](http://code.google.com/p/avalanche/wiki/Mask_syntax)|
| --dump-calls  |             |Dump the list of functions manipulating with tainted data to calldump.log|
| --func-name=name |             |The name of function that should be used for separate function analysis (may be used multiple times)|
| --func-file=name |             |The path to the file with the list of functions that should be used for separate function analysis (described [here](Specifying_functions_for_separate_analysis.md))|
| --suppress-subcalls |             |Ignore conditions in a nested function calls during separate analysis|
| **[distributed analysis](http://code.google.com/p/avalanche/wiki/Distributed_avalanche)** |             |                 |
| --distributed |             |Tell Avalanche that it should connect to distribution server and run distributed analysis|
| --dist-host=IPv4\_address | 127.0.0.1   |IP address of the distribution server|
| --dist-port=number | 12200       |Port number of the distribution server|
| --protect-main-agent |             |Do not send inputs to the remore agents, if the overall number of inputs do not exceed 5 `*` number\_of\_agents|

### Avalanche output ###

If input data is received from file and avalanche finds a crash, then it dumps a file with the name 'exploit\_i\_j' where 'j' is the number of the file (multiple input files may be specified with '--filename' option) and 'i' is the number of the exploit. If the input file is single, then the generated "inputs of death" have names 'exploit\_0\_0', 'exploit\_1\_0', 'exploit\_2\_0' and so on. If the generated file doesn't cause a crash, but still demonstrates an error in the program (i. e. the bug is found by memcheck), then it has the name 'memcheck\_i\_j'.

If input data is received from socket, then the generated files have the names 'exploit\_i' and/or 'memcheck\_i' where 'i' is the number of detected defect. See [Samples](Samples.md) wiki page for some examples.

Avalanche also dumps stack trace of each unique exploit.

In the case of distributed analysis, special prefix is added to the name of the each input file generated by the remote Avalanche agent. For example, 'branch0\_exploit\_0\_0', 'branch1\_exploit\_0\_0', etc, so that exploits do not rewrite each other. Exploits found by different agents aren't collected in one place; they remain on the machine where they were detected.

After the end of the analysis Avalanche prints exploit report, where all the detected exploits are sorted into groups according to stack trace of the crash. This really simplifies the examination of analysis results.