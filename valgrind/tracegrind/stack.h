#ifndef __STACK_H
#define __STACK_H

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcfile.h"

struct _stack
{
  void** buf;
  Int cursize;
  Int curocc;
};

typedef struct _stack Stack;

void initStack(Stack* s);

void push(Stack* s, void* elem);

void* pop(Stack* s);

#endif
