#ifndef __AVALANCHE_H
#define __AVALANCHE_H

#define SIZE 1

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
  Addr64 key;  
};

typedef struct _bbNode bbNode;

HWord hashCode(Char* str);

#endif
