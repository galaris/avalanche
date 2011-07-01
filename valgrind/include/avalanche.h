#ifndef __AVALANCHE_H
#define __AVALANCHE_H

#define SIZE 1

#if defined(VGP_arm_linux)
enum 
{
  ARMCondEQ, ARMCondNE, ARMCondHS, ARMCondLO,
  ARMCondMI, ARMCondPL, ARMCondVS, ARMCondVC,
  ARMCondHI, ARMCondLS, ARMCondGE, ARMCondLT,
  ARMCondGT, ARMCondLE, ARMCondAL, ARMCondNV
};
#elif defined(VGP_x86_linux) || defined(VGP_amd64_linux)
enum 
{
  X86CondO, X86CondNO, X86CondB, X86CondNB,
  X86CondZ, X86CondNZ, X86CondBE, X86CondNBE,
  X86CondS, X86CondNS, X86CondP, X86CondNP,
  X86CondL, X86CondNL, X86CondLE, X86CondNLE,
  X86CondAlways = 16  /* HACK */
};
#endif

enum
{
  BVLT,  //unsigned less
  BVGE,  //unsigned greater or equal
  IFT,   //equal
  IFNOT, //not equal
  BVLE,  //unsigned less or equal
  BVGT,  //unsigned greater
  SBVLT,  //signed less
  SBVGE,  //signed greater or equal
  SBVLE,  //signed less or equal
  SBVGT,  //signed greater
  INVALID
};

struct _fdsNode 
{
  struct _fdsNode* next;
  HWord key;  
  HChar* name;
  ULong offs;
  ULong size;
  Int seqnum;
};

typedef struct _fdsNode fdsNode; 

struct _stringNode
{
  struct _stringNode* next;
  HWord key;
  Bool declared;
  Char* filename;
  Int filenum;
};

typedef struct _stringNode stringNode;

struct _replaceData
{
  UChar* data;
  Int length;
};

typedef struct _replaceData replaceData;

struct _bbNode 
{
  struct _sizeNode* next;
  UWord key;  
};

typedef struct _bbNode bbNode;

HWord hashCode(Char* str);

#endif
