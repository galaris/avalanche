### Enabling CLO checking ###
Enable command line checking with --check-argv=list option. You can specify list as following:

  * list="N<sub>1</sub> N<sub>2</sub> N<sub>3</sub> ... N<sub>n</sub>" (use '"' to specify multiple arguments to check). Numbers represent arguments' indexes. N<sub>i</sub> corresponds to `argv[Ni]`. Specifying 0 as one of the indexes won't cause any effect.
  * list=all to check all arguments (except `argv[0]`).

Example:

Here only arg2 will be changed.
```
./inst/bin/avalanche --check-argv=2 executable_name arg1 arg2 arg3
```

And here arg2 and arg3 will be changed.

```
./inst/bin/avalanche --check-argv="2 3" executable_name arg1 arg2 arg3
```

### Additional options ###

You can also enable more intelligent checking with --protect-arg-name option. With this option avalanche will change only part of argument after '=' symbol if there is initially '=' in it.


Example:
```
./inst/bin/avalanche --check-argv=1 --protect-arg-name executable_name --number=1234
```

In this case only the actual number, i.e. 1234, will be changed.