Masks are VERY simple.

Mask is a list of numbers and intervals. Numbers are hexadecimal (may start with 0x). Interval is two numbers divided by '-' symbol. Numbers and intervals are divided by space symbols (excluding newline symbols).

Samples:

```
0xf 0x12-0x13f
```

0xf byte and all the bytes from 0x12 until 0x13f (including the borders) are considered to be tainted.

```
0 3-5 7 - 9 f
```

Only the bytes with positions 0, 3, 4, 5, 7, 8, 9, f are tainted.

Something probably a bit weird:

Newlines divide the masks for multiple sources of tainted data (multiple files or multiple connections in case of sockets). Blank line means that some source should be completely ignored.

```
0xa-0xf
3 5

0x15 - 0x34 0x5a-0x12b
```

The following bytes are tainted: the bytes from 0xa to 0xf in the first source (file or socket connection), bytes on positions 3 and 5 in the second source, and the bytes from 0x15 to 0x34 and from 0x5a to 0x12b in the fourth source. The third source doesn't contain anything tainted.