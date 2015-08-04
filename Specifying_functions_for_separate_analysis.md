The rules for a function list (general description of avalanche options for separate analysis are given [here](Using_Avalanche.md)) are the following:

Each function is specified on a separate line.
Each specified function will be used by avalanche only in case of exact match of the name (for both C and C++ functions) or signature (for C++ function).

The following list was generated on flvdumper (see [gnash](http://www.gnu.org/software/gnash/)) with --dump-calls option and shows how functions are identified by avalanche:

```
amf::Flv::decodeHeader(boost::shared_ptr<amf::Buffer>)
main
amf::Buffer::resize(unsigned int)
malloc
imalloc
huge_malloc
chunk_alloc_dss
pages_map
amf::Flv::decodeMetaData(unsigned char*, unsigned int)
arena_malloc
arena_malloc_small
amf::AMF::extractAMF(unsigned char*, unsigned char*)
amf::AMF::extractProperty(unsigned char*, unsigned char*)
amf::Element::setName(unsigned char*, unsigned int)
```

Two additional features are available for specifying functions:

### Commenting functions ###
To avoid deleting names from the list **#** can be used to indicate a commented function. This function will not be treated as specified for separate analysis.

```
...
#main
amf::Buffer::resize(unsigned int)
...
```

### Wildcards ###
Functions specified in the list will be used during separate analysis only in case of exact match of either the name (for both C and C++ functions) or full signature (for C++ functions). However, **?** can be used to indicate any sequence of symbols. For example, the following line in the list

```
amf::?
```

will match any function that has a signature starting with "amf::". This feature is useful in a number of cases (dealing with C++ template functions or specifying all functions of one class).