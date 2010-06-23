#include "stpbuffer.h"

extern Bool stopTrace;

void initStpBuffer(StpBuffer* traces)
{
  traces->traces = VG_(malloc)("stack", sizeof(Stack));
  initStack(traces->traces);
}

void forkTrace(StpBuffer* traces, Char* condinv, Char* cond)
{
  Int length = 0;
  Int lengthinv = 0;
  while (cond[length] != '\0')
  {
    length++;
  }
  while (condinv[lengthinv] != '\0')
  {
    lengthinv++;
  }
  Int i = 0;
  Int border = traces->traces->curocc;
  for (; i < border; i++)
  {
    Int fdinv = (Int) traces->traces->buf[i];
    Char name[64];
    VG_(sprintf)(name, "trace%d.log", border + i);
    SysRes sr = VG_(open)(name, VKI_O_RDWR | VKI_O_TRUNC | VKI_O_CREAT, VKI_S_IRWXU | VKI_S_IRWXG | VKI_S_IRWXO);
    Int fd = sr.res;
    VG_(close)(fdinv); 
    VG_(sprintf)(name, "trace%d.log", i);
    sr = VG_(open)(name, VKI_O_RDWR, VKI_S_IRUSR | VKI_S_IWUSR);
    fdinv = sr.res;
    Char c;
    Int res;
    while ((res = VG_(read)(fdinv, &c, 1)) != 0)
    {
      VG_(write)(fd, &c, 1);
    }
    VG_(write)(fd, cond, length);
    VG_(write)(fdinv, condinv, lengthinv);
    traces->traces->buf[i] = (void*) fdinv;
    push(traces->traces, (void*) fd);
  }
}

void addToTrace(StpBuffer* traces, Char* s)
{
  if (stopTrace) return;
  Int length = 0;
  while (s[length] != '\0')
  {
    length++;
  }  
  if (traces->traces->curocc != 0)
  {
    Int i = 0;
    Int border = traces->traces->curocc;
    for (; i < border; i++)
    {
      Int fd = (Int) traces->traces->buf[i];
      VG_(write)(fd, s, length);
    }
  }
  else
  {
    SysRes fd = VG_(open)("trace0.log", VKI_O_RDWR | VKI_O_TRUNC | VKI_O_CREAT, VKI_S_IRWXU | VKI_S_IRWXG | VKI_S_IRWXO);
    if (fd.res != 0)
    {
      VG_(write)(fd.res, s, length); 
      push(traces->traces, (void*) fd.res);
    }    
  }
} 

void dumpTraces(StpBuffer* traces)
{
  Int i = 0;
  for (; i < traces->traces->curocc; i++)
  {
    VG_(write)((Int) traces->traces->buf[i], "QUERY(FALSE);\n", 14);
    VG_(close)((Int) traces->traces->buf[i]);
  }
}

void cleanTraces(StpBuffer* traces)
{
  Int i = 0;
  for (; i < traces->traces->curocc; i++)
  {
    VG_(close)((Int) traces->traces->buf[i]);
    Char name[64];
    VG_(sprintf)(name, "trace%d.log", i);
    SysRes fd = VG_(open)(name, VKI_O_RDWR | VKI_O_TRUNC | VKI_O_CREAT, VKI_S_IRWXU | VKI_S_IRWXG | VKI_S_IRWXO);
    VG_(write)(fd.res, "bottom is reached\n", 18);
    VG_(close)(fd.res);
  }
}

/*
void initStpBuffer(StpBuffer* traces)
{
  traces->traces = VG_(malloc)("stack", sizeof(Stack));
  initStack(traces->traces);
}

Buffer* getTrace(StpBuffer* traces, Int i)
{
  if ((i >= 0) && (i < traces->traces->curocc))
  {
    return traces->traces->buf[i];
  }
  else
  {
    return NULL;
  }
}

void fork(StpBuffer* traces, Char* condinv, Char* cond)
{
  if (traces->traces->curocc != 0)
  {
    Int i = 0;
    Int border = traces->traces->curocc;
    for (; i < border; i++)
    {
      Buffer* binv = (Buffer*) traces->traces->buf[i];
      Buffer* b = VG_(malloc)("buffer", sizeof(Buffer));
      copyBuffer(b, binv);
      add(b, cond);
      add(binv, condinv);
      push(traces->traces, b);
    }
  }
  else
  {
    Buffer* binv = VG_(malloc)("buffer", sizeof(Buffer));
    Buffer* b = VG_(malloc)("buffer", sizeof(Buffer));
    initBuffer(binv, condinv);
    initBuffer(b, cond);
    push(traces->traces, binv);
    push(traces->traces, b);
  }
}

void addToTrace(StpBuffer* traces, Char* s)
{
  if (traces->traces->curocc != 0)
  {
    Int i = 0;
    Int border = traces->traces->curocc;
    //VG_(printf)("border=%d\n", border);
    for (; i < border; i++)
    {
      Buffer* b = (Buffer*) traces->traces->buf[i];
      add(b, s);
    }
  }
  else
  {
    Buffer* b;
    b = VG_(malloc)("buffer", sizeof(Buffer));
    initBuffer(b, s);
    push(traces->traces, b);
  }
} 

void printTraces(StpBuffer* traces)
{
  Int i = 0;
  for (; i < traces->traces->curocc; i++)
  {
    Buffer* b = getTrace(traces, i);
    Char* t = toString(b);
    VG_(printf)("%s", t);
    VG_(printf)("\n#################\n");
  }
}

void dumpTraces(StpBuffer* traces)
{
  Int i = 0;
  for (; i < traces->traces->curocc - 1; i++)
  {
    Char name[64];
    VG_(sprintf)(name, "trace%d.log", i);
    SysRes fd = VG_(open)(name, VKI_O_RDWR | VKI_O_TRUNC | VKI_O_CREAT, VKI_S_IRUSR | VKI_S_IWUSR);
    if (fd.res != 0)
    {
      Buffer* b = getTrace(traces, i);
      add(b, "QUERY(FALSE);\n");
      Char* t = toString(b);
      VG_(write)(fd.res, t, b->curocc);    
      VG_(close)(fd.res);
    }
  }
}
*/

