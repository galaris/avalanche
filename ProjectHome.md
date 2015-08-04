## Avalanche overview ##

  * Automatically finds critical software errors
  * Generates "input of death" for each detected error
  * Tracks the flow of "tainted" data in the program
  * Iteratively generates a sequence of inputs to increase the coverage and find new errors
  * Implements dynamic analysis based on open-source [Valgrind framework](http://valgrind.org/), and [STP (Simple Theorem Prover)](http://sites.google.com/site/stpfastprover/)
  * Runs on x86/Linux and x86\_64/Linux

See **[Project Wiki](http://code.google.com/p/avalanche/wiki/Avalanche)** for detailed description, list of detected bugs and usage samples.

You can contact us on [mailing list](http://groups.google.com/group/avalanche-users).

## News ##


---


**16 Nov 2011:** Avalanche-0.6 is [released](http://code.google.com/p/avalanche/downloads/list)

**Release notes**

  * Version 0.5 featured ARM support, version 0.6 added Android support. Build and use instructions are included in README.arm and README.android respectively.
  * Added split-mode for effective use with ARM devices/emulators.
  * Upgraded Valgrind version (necessary for ARM & Android-ARM support).
  * Improved logging system.
  * Fixed a number of bugs and other issues.


---


**22. Feb 2011:** Avalanche-0.4 is [released](http://code.google.com/p/avalanche/downloads/list)

**Release notes**

  * Avalanche now uses an up-to-date version of Valgrind.
  * A number of minor bugs are fixed.


---


**1. Dec 2010:** Avalanche-0.3 is [released](http://code.google.com/p/avalanche/downloads/list)

**Release notes**

  * STP queries may now be checked [in parallel](http://code.google.com/p/avalanche/wiki/Multiple_threads_for_STP_queries)
  * A simple model for distributed analysis is [implemented](http://code.google.com/p/avalanche/wiki/Distributed_avalanche)

These features speed up the analysis and let Avalanche find defects that otherwise remain unreached. [Crash in LLVM](http://llvm.org/bugs/show_bug.cgi?id=8494) detected by Avalanche is an example.


---


**10. Sep 2010:** Avalanche-0.2 is [released](http://code.google.com/p/avalanche/downloads/list)

**Release notes**

  * Added support for [input file masks](http://code.google.com/p/avalanche/wiki/Input_masks_and_function_filtering?ts=1284145326&updated=Input_masks_and_function_filtering#Input_masks)
  * Added [separate function analysis](http://code.google.com/p/avalanche/wiki/Input_masks_and_function_filtering?ts=1284145326&updated=Input_masks_and_function_filtering#Function_filtering)
  * Added sorting of the detected exploits according to their stack traces

This makes analysis performed by Avalanche more efficient. Crashes in [Mono](https://bugzilla.novell.com/show_bug.cgi?id=636794) and [Parrot VM](http://trac.parrot.org/parrot/ticket/1740) are examples of bugs discovered only when using new features.