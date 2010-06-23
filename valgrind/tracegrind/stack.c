#include "stack.h"

void initStack(Stack* s)
{
  s->buf = VG_(malloc)("stack", 256 * sizeof(void*));
  s->curocc = 0;
  s->cursize = 256;
}

void push(Stack* s, void* elem)
{
  if (s->curocc == s->cursize)
  {
    s->buf = VG_(realloc)("stack", s->cursize * 2 * sizeof(void*));
    s->cursize *= 2;
  }
  s->buf[s->curocc++] = elem;
}

void* pop(Stack* s)
{
  if (s->curocc > 0)
  {
    s->curocc--;
    return s->buf[s->curocc];
  }
  else
  {
    return NULL;
  }
}

