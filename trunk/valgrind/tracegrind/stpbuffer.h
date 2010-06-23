#ifndef __STP_BUFFER_H
#define __STP_BUFFER_H

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_vki.h"

#include "stack.h"

struct _stp_buffer
{
  Stack* traces;
};

typedef struct _stp_buffer StpBuffer;

void initStpBuffer(StpBuffer* traces);

void forkTrace(StpBuffer* traces, Char* condinv, Char* cond);

void addToTrace(StpBuffer* traces, Char* s);

void dumpTraces(StpBuffer* traces);

void cleanTraces(StpBuffer* traces);


#endif
