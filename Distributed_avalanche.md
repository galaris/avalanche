## Distributed analysis model ##

Avalanche distributed analysis is based on the concept of using several agents to process branches of condition tree. One of the agents in the model (referred to as main avalanche agent) is the source of inputs for other (worker) agents. Communication between agents and main avalanche is handled by distributed avalanche server. The following scheme depicts the components of distributed model and their interaction.

![http://avalanche.googlecode.com/files/distributed-scheme.jpg](http://avalanche.googlecode.com/files/distributed-scheme.jpg)

1. Distributed avalanche server (av-dist). The server accepts connection from agents and main avalanche, passes requests from agents and responses from main avalanche. There are two types of requests:

  * input+options - agent requests starting options and initial input for avalanche.
  * input - agent requests initial input for avalanche.

2. Main avalanche agent (main avalanche). An instance of avalanche that starts distributed analysis using initial input provided by user. Additional options specified when starting main avalanche ([list of avalanche options](http://code.google.com/p/avalanche/wiki/Using_Avalanche)) are used by all worker agents. After the end of each analysis iteration main avalanche processes pending requests from server. It keeps the best input (input with the highest score) or several best inputs (if --protect-main-agent is used) and passes other inputs in response to worker agent requests'. When main avalanche runs out of inputs the analysis is over.

3. Avalanche worker agent (av-agent). Upon connection to the server worker agent sends request for starting options and an input. After the request has been satisfied it runs an instance of avalanche with received options and using input as initial. When avalanche finishes work worker agent saves exploit info and requests another input. Worker agent starts an instance of avalanche with the same starting options and using newly received input. This process continues until main avalanche runs out of inputs.

**Distributed analysis requires several rules to be followed:**

  * Binary executables are not copied through the network - each machine running av-agent should have the analysed program installed. Path to executable should match the path specified in command line for main avalanche.

  * Only files specified in main avalanche command line (as --filename=name) are copied through the network and are multiplied locally when multiple threads for STP queries are used (to avoid potential conflicts).

## Running distributed analysis ##

Here is a [dist3.c](http://code.google.com/p/avalanche/source/browse/trunk/samples/simple/dist3.c) sample. To run distributed analysis, first start the distribution server. It takes a single option - port number to listen for the incoming connections.

```
user@machine1:$ ./inst/bin/av-dist 10000
```

Distribution server terminates when the analysis is over.

Then start a number of agents on different machines. Each agent requires two necessary options: IP address and port number of the distribution server. The third possible option is '--request-non-zero'. This option will force instance of Avalanche run by agent to request input from the server if all its' inputs have zero score.

```
user@machine2:$ ./inst/bin/av-agent <machine1 IP address> 10000
```

```
user@machine3:$ ./inst/bin/av-agent <machine1 IP address> 10000
```

Finally, start avalanche, adding --distributed, --dist-host and --dist-port options:

```
user@machine1:$ inst/bin/avalanche --distributed --dist-host=<machine1 IP address> --dist-port=10000 --filename=samples/simple/seed samples/simple/dist3 samples/simple/seed
```

Avalanche should find three exploits, one on each of the three Avalanche agents involved.

```
user@mechine1:$ cat exploit_0_0
bar
```

```
user@mechine2:$ cat branch0_exploit_0_0
foo
```

```
user@mechine3:$ cat branch0_exploit_0_0
wtf
```