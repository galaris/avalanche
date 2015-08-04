# qtdump #

Running avalanche without new features:

1) seed is 712 bytes, all zeros

2) launching with
```
user@machine:$ ./inst/bin/avalanche --filename=seed ../libquicktime-1.1.3/inst/bin/qtdump seed 
```

Results:

1st bug after 1033 seconds from start, bug info is
```
Process terminating with default action of signal 11 (SIGSEGV)
 Access not within mapped region at address 0xC
   at 0x4036171: idx1_build_index (avi_riff.c:383)
   by 0x40364D6: quicktime_import_avi (avi_riff.c:464)
   by 0x402DF1F: quicktime_read_info (lqt_quicktime.c:1520)
   by 0x402EB4C: do_open (lqt_quicktime.c:1790)
   by 0x402ECA8: quicktime_open (lqt_quicktime.c:1839)
   by 0x80485FA: main (dump.c:39)
```

2nd bug after 1034 seconds from start, bug info is
```
Process terminating with default action of signal 11 (SIGSEGV)
 Access not within mapped region at address 0x0
   at 0x41875CC: mempcpy (in /lib/tls/i686/cmov/libc-2.7.so)
   by 0x417B347: _IO_sgetn (in /lib/tls/i686/cmov/libc-2.7.so)
   by 0x416F38D: fread (in /lib/tls/i686/cmov/libc-2.7.so)
   by 0x407E4A7: quicktime_read_data (util.c:248)
   by 0x40356FE: quicktime_read_riff (avi_riff.c:99)
   by 0x402DEA3: quicktime_read_info (lqt_quicktime.c:1510)
   by 0x402EB4C: do_open (lqt_quicktime.c:1790)
   by 0x402ECA8: quicktime_open (lqt_quicktime.c:1839)
   by 0x80485FA: main (dump.c:39)
```

Avalanche worked for 40 minutes, then was stopped. No new bugs except two discovered were found.

Running avalanche with input mask

1) seed is 712 bytes:
```
user@machine:$ hexdump seed
0000000 4952 4646 0000 0000 5641 2049 6469 3178
0000010 0000 0000 0000 0000 0000 0000 0000 0000
*
00002c0 0000 0000 0000 0000                    
00002c8
```
2) mask contains the following:
```
0-3 0x8-0xf
```
3) launching with
```
user@machine:$ ./inst/bin/avalanche --mask=mask --filename=seed ../libquicktime-1.1.3/inst/bin/qtdump seed 
```


Results:

1st bug after 6 seconds from start, bug info is
```
Process terminating with default action of signal 11 (SIGSEGV)
 Access not within mapped region at address 0xC
   at 0x4036171: idx1_build_index (avi_riff.c:383)
   by 0x40364D6: quicktime_import_avi (avi_riff.c:464)
   by 0x402DF1F: quicktime_read_info (lqt_quicktime.c:1520)
   by 0x402EB4C: do_open (lqt_quicktime.c:1790)
   by 0x402ECA8: quicktime_open (lqt_quicktime.c:1839)
   by 0x80485FA: main (dump.c:39)
```

2nd bug after 7 seconds from start, bug info is
```
Process terminating with default action of signal 11 (SIGSEGV)
 Access not within mapped region at address 0x0
   at 0x41875CC: mempcpy (in /lib/tls/i686/cmov/libc-2.7.so)
   by 0x417B347: _IO_sgetn (in /lib/tls/i686/cmov/libc-2.7.so)
   by 0x416F38D: fread (in /lib/tls/i686/cmov/libc-2.7.so)
   by 0x407E4A7: quicktime_read_data (util.c:248)
   by 0x40356FE: quicktime_read_riff (avi_riff.c:99)
   by 0x402DEA3: quicktime_read_info (lqt_quicktime.c:1510)
   by 0x402EB4C: do_open (lqt_quicktime.c:1790)
   by 0x402ECA8: quicktime_open (lqt_quicktime.c:1839)
   by 0x80485FA: main (dump.c:39)
```

Avalanche worked for 40 minutes, then was stopped. No new bugs except two discovered were found.

## swfdump ##

Running avalanche without new features:

1) seed is 712 bytes, all zeros

2) launching with
```
user@machine:$ ./inst/bin/avalanche --filename=seed ../swftools-0.9.0/inst/bin/swfdump seed 
```

Results:

1st bug after 10 seconds, bug info is
```
Process terminating with default action of signal 11 (SIGSEGV)
 Access not within mapped region at address 0x0
   at 0x8061118: swf_GetU32 (rfxswf.c:127)
   by 0x8064D80: swf_ReadSWF2 (rfxswf.c:1478)
   by 0x8064EB8: swf_ReadSWF (rfxswf.c:1507)
   by 0x804DA1C: main (swfdump.c:1026)
```

Avalanche worked for 30 minutes, then was stopped. No new bugs except the one discovered were found.

Running avalanche with function filtering (specified function was swf\_ReadSWF2) and suppressing subcalls:

1) seed is 712 bytes, all zeros

2) launching with
```
user@machine:$ ./inst/bin/avalanche --func-filter=conds --func-name=swf_ReadSWF2 --suppress-subcalls --filename=seed ../swftools-0.9.0/inst/bin/swfdump seed 
```

Results:

1st bug after 7 seconds, bug info is
```
Process terminating with default action of signal 11 (SIGSEGV)
 Access not within mapped region at address 0x0
   at 0x8061118: swf_GetU32 (rfxswf.c:127)
   by 0x8064D80: swf_ReadSWF2 (rfxswf.c:1478)
   by 0x8064EB8: swf_ReadSWF (rfxswf.c:1507)
   by 0x804DA1C: main (swfdump.c:1026)
```

Avalanche worked for 303 seconds and exited normally, no new bugs were found.


Running avalanche with function filtering (specified function was swf\_ReadSWF2), suppressing subcalls and using input filter:

1) seed is 712 bytes:
```
user@machine:$hexdump seed
0000000 5746 0453 0000 0000 0000 0000 0000 0000
0000010 0000 0000 0000 0000 0000 0000 0000 0000
*
00002c0 0000 0000 0000 0000                    
00002c8
```
2) mask contains the following:
```
0-3
```

3) launching with
```
user@machine:$ ./inst/bin/avalanche --func-filter=conds --func-name=swf_ReadSWF2 --suppress-subcalls --mask=mask --filename=seed ../swftools-0.9.0/inst/bin/swfdump seed 
```

Results:

1st bug after 3 seconds, bug info is
```
Process terminating with default action of signal 11 (SIGSEGV)
 Access not within mapped region at address 0x0
   at 0x8061118: swf_GetU32 (rfxswf.c:127)
   by 0x8064D80: swf_ReadSWF2 (rfxswf.c:1478)
   by 0x8064EB8: swf_ReadSWF (rfxswf.c:1507)
   by 0x804DA1C: main (swfdump.c:1026)
```

Avalanche worked for 280 seconds and exited normally, no new bugs were found.

## Monodis ##

inst/bin/avalanche --trace-children --debug --mask=[mask](http://avalanche.googlecode.com/files/mask) --verbose --filename=TestArrays.dll ./mono-2.6.7/mono/dis/monodis TestArrays.dll

produces a number of [exploit](http://avalanche.googlecode.com/files/exploit_5_0) files

## Mono ##

inst/bin/avalanche --trace-children --mask=[mask](http://avalanche.googlecode.com/files/mask_mono) --debug --verbose --filename=[Hello.exe](http://avalanche.googlecode.com/files/Hello.exe)  mono-2.6.7/inst/bin/mono mono-2.6.7/inst/bin/Hello.exe

[exploit](http://avalanche.googlecode.com/files/exploit_0_0)

## pbc\_dump (parrot) ##

inst/bin/avalanche --mask=[mask](http://avalanche.googlecode.com/files/mask_pbc_dump) --debug --verbose --filename=[PGE.pbc](http://avalanche.googlecode.com/files/PGE.pbc) parrot-2.6.0/inst/bin/pbc\_dump -d PGE.pbc

[exploit](http://avalanche.googlecode.com/files/pbc_dump_exploit_0_0)
[exploit](http://avalanche.googlecode.com/files/pbc_dump_exploit_1_0)

## llc (llvm) ##

inst/bin/avalanche --debug --verbose  --mask=[mask\_llvm](http://avalanche.googlecode.com/files/mask_llvm) --filename=[hello.bc](http://avalanche.googlecode.com/files/hello.bc) llvm-2.7/inst/bin/llc hello.bc

a significant speedup for detection of [exploit](http://avalanche.googlecode.com/files/exploit_126_0)