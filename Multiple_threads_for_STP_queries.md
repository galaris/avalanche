Avalanche can use multiple threads to process STP queries (and the corresponding Covgring checks) emitted during one run of Tracegrind.

To run Avalanche with multiple threads for STP queries, use --stp-threads=number option, where number is the amount of simultaneously running threads. You may also use --stp-threads=auto notation. In this case the number of CPU cores is taken.