
/*--------------------------------------------------------------------------------*/
/*-------------------------------- AVALANCHE -------------------------------------*/
/*--- Tracegrind. Transforms IR tainted trace to STP declarations.   tg_main.c ---*/
/*--------------------------------------------------------------------------------*/

/*
   This file is part of Tracegrind, the Valgrind tool,
   which tracks tainted data coming from the specified file
   and converts IR trace to STP declarations.

   Copyright (C) 2009 Ildar Isaev
      iisaev@ispras.ru

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.
*/

#include "pub_tool_basics.h"
#include "pub_tool_options.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_hashtable.h"
#include "pub_tool_xarray.h"
#include "pub_tool_clientstate.h"
#include "pub_tool_aspacemgr.h"
#include "pub_tool_vki.h"
#include "pub_tool_vkiscnums.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_machine.h"
#include "pub_tool_threadstate.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_stacktrace.h"
#include "pub_tool_libcfile.h"
#include "libvex_ir.h"

#include <avalanche.h>

#include "buffer.h"
#include "copy.h"
#include "parser.h"

/* This is fairly important thing: without this define we leave ASSERTs
   when throwing out QUERYs during separate function analysis. This basically
   means that we won't ever invert conditions not in specified functions.
   In theory, this is "more" right way - we get less cases of divergent
   runs. In practice it leads to Avalanche ending quickly without any
   found results if we use "bad input".
   That's why define is currently used. */
#define CUT_ASSERT_WITH_QUERY

//#define TAINTED_TRACE_PRINTOUT
//#define TAINTED_BLOCKS_PRINTOUT
//#define CALL_STACK_PRINTOUT

enum {
    X86CondO      = 0,  /* overflow           */
    X86CondNO     = 1,  /* no overflow        */

    X86CondB      = 2,  /* below              */
    X86CondNB     = 3,  /* not below          */

    X86CondZ      = 4,  /* zero               */
    X86CondNZ     = 5,  /* not zero           */

    X86CondBE     = 6,  /* below or equal     */
    X86CondNBE    = 7,  /* not below or equal */

    X86CondS      = 8,  /* negative           */
    X86CondNS     = 9,  /* not negative       */

    X86CondP      = 10, /* parity even        */
    X86CondNP     = 11, /* not parity even    */

    X86CondL      = 12, /* jump less          */
    X86CondNL     = 13, /* not less           */

    X86CondLE     = 14, /* less or equal      */
    X86CondNLE    = 15, /* not less or equal  */

    X86CondAlways = 16  /* HACK */
};

struct _taintedNode
{
  struct _taintedNode* next;
  HWord key;
  HChar* filename;
  ULong offset;
};

typedef struct _taintedNode taintedNode;

struct _size2Node
{
  UShort size;
  //Bool declared;
};

typedef struct _size2Node size2Node;

struct _sizeNode
{
  struct _sizeNode* next;
  Addr64 key;
  size2Node* temps;
  Int tempsnum;
  UInt visited;
};

typedef struct _sizeNode sizeNode;

static Addr curIAddr;
Bool filterConditions = False;
Bool filterDangerous = False;

Bool suppressSubcalls = False;

VgHashTable funcNames;
VgHashTable funcSignatures;

Char* diFunctionName;
Char* diVarName;

Bool newSB;
IRSB* printSB;

Bool dumpCalls;
Int fdfuncFilter;

VgHashTable inputFilter;
Bool inputFilterEnabled = False;

//Bool checkFParameters = True;

VgHashTable taintedMemory;
VgHashTable taintedRegisters;
VgHashTable taintedTemps = NULL;

VgHashTable startAddr;

extern VgHashTable fds;
extern HChar* curfile;
extern Int cursocket;
extern ULong curoffs;
extern ULong cursize;

VgHashTable tempSizeTable;
sizeNode* curNode;

ULong start = 0;

Bool isRead = False;
Bool isOpen = False;
Bool isMap = False;
extern Bool curDeclared;
extern Bool accept;
extern Bool connect;
extern Bool socket;
extern Bool isRecv;
Bool checkPrediction = False;
extern Bool sockets;
extern Bool datagrams;
Bool replace = False;
static Int socketsNum = 0;
static Int socketsBoundary;
static replaceData* replace_data;
Bool dumpPrediction = False;
Bool divergence = False;
Bool* prediction;
Bool* actual;

Addr64 curblock = 0;

Int fdtrace;
Int fddanger;
extern VgHashTable inputfiles;
extern UShort port;
extern UChar ip1, ip2, ip3, ip4;

Int depth = 0;
Int invertdepth = 0;
Int curdepth;

Int memory = 0;
Int registers = 0;
UInt curvisited;

static 
Bool getFunctionName(Addr addr, Bool onlyEntry, Bool showOffset)
{
  Bool continueFlag = False;
  if (onlyEntry)
  {
    continueFlag = VG_(get_fnname_if_entry) (addr, diFunctionName, 256);
  }
/* showOffset is used only for checking formal parameters */
  else if (showOffset)
  {
    continueFlag = VG_(get_fnname_w_offset) (addr, diFunctionName, 256);
  }
  else
  {
    continueFlag = VG_(get_fnname) (addr, diFunctionName, 256);
  }
  if (continueFlag)
  {
    return True;
  }
  return False;
}

static
Bool useFiltering (void)
{
  /* Look up the top function in call stack only */
  if (suppressSubcalls)
  {
    VG_(memset) (diFunctionName, 0, VG_(strlen) (diFunctionName));
    if (getFunctionName(curIAddr, False, False))
    {
      return (VG_(HT_lookup) (funcNames, hashCode(diFunctionName)) != NULL || checkWildcards(diFunctionName));
    }
    return False;
  }
  /* Look up call stack and try to match function on any position */
  else
  {
#define STACK_LOOKUP_DEPTH 30
    Addr ips[STACK_LOOKUP_DEPTH];
    Addr sps[STACK_LOOKUP_DEPTH];
    Addr fps[STACK_LOOKUP_DEPTH];
    Int found = VG_(get_StackTrace) (VG_(get_running_tid) (), ips, STACK_LOOKUP_DEPTH, sps, fps, 0);
#undef STACK_LOOKUP_DEPTH
    Int i;
    for (i = 0; i < found; i ++)
    {
      VG_(memset) (diFunctionName, 0, VG_(strlen) (diFunctionName));
      if (getFunctionName(ips[i], False, False))
      {
        if (VG_(HT_lookup) (funcNames, hashCode(diFunctionName)) != NULL || checkWildcards(diFunctionName))
        {
          return True;
        }
      }
    }
  }
  return False;
}

/* ULong is typedeffed as unsigned long long and getDecimalValue
   result is used as unsigned long only, so I'll switch to HWord */
static
HWord getDecimalValue(IRExpr* e, HWord value)
{
  if (e->tag == Iex_Const)
  {
    IRConst* con = e->Iex.Const.con;
    switch (con->tag)
    {
      case Ico_U1:	return con->Ico.U1;
      case Ico_U8:	return con->Ico.U8;
      case Ico_U16:	return con->Ico.U16;
      case Ico_U32:	return con->Ico.U32;
      case Ico_U64:	return con->Ico.U64;
      default:		return 0; break;
    }
  }
  else
  {
    return value;
  }
}

static
Addr64 getLongDecimalValue(IRExpr* e, Addr64 value)
{
  if (e->tag == Iex_Const)
  {
    IRConst* con = e->Iex.Const.con;
    switch (con->tag)
    {
      case Ico_U1:	return con->Ico.U1;
      case Ico_U8:	return con->Ico.U8;
      case Ico_U16:	return con->Ico.U16;
      case Ico_U32:	return con->Ico.U32;
      case Ico_U64:	return con->Ico.U64;
      default:		return 0; break;
    }
  }
  else
  {
    return value;
  }
}

static
void translateLongToPowerOfTwo(IRExpr* e, Addr64 value)
{
  Addr64 a = 0x1;
  Addr64 i = 1;
  Char s[256];
  Int l;
  for (; i < value; i++)
  {
    a <<= 1;
  }
  l = VG_(sprintf)(s, "0hex%016llx", a);
  my_write(fdtrace, s, l);
  my_write(fddanger, s, l);
}

static
void translateToPowerOfTwo(IRExpr* e, IRExpr* value, UShort size)
{
  Addr64 a = 0x1;
  HWord i = 1;
  HWord v = (HWord) value;
  Char s[256];
  Char format[256];
  Int l = 0;
  if (e->tag == Iex_Const)
  {
    IRConst* con = e->Iex.Const.con;
    switch (con->tag)
    {
      case Ico_U1:	v = con->Ico.U1;
			break;
      case Ico_U8:	v = con->Ico.U8;
			break;
      case Ico_U16:	v = con->Ico.U16;
			break;
      case Ico_U32:	v = con->Ico.U32;
			break;
      case Ico_U64:	v = con->Ico.U64;
			break;
      default:		break;
    }
  }
  for (; i < v; i++)
  {
    a <<= 1;
  }
  /* If with two switches changed to these */
  VG_(sprintf) (format, "0%s%%%s%dllx", (e->tag != Iex_Const && size == 1) ? "bin" : "hex", (size == 1) ? "" : "0", size >> 2);
  l = VG_(sprintf) (s, format, a);
  my_write(fdtrace, s, l);
  my_write(fddanger, s, l);
}

static
void translateLongValue(IRExpr* e, Addr64 value)
{
  Char s[256];
  Int l = VG_(sprintf)(s, "0hex%016llx", value);
  my_write(fdtrace, s, l);
  my_write(fddanger, s, l);
}

static
void translateValue(IRExpr* e, IRExpr* value)
{
  Char s[256];
  Int l = 0;
  if (e->tag == Iex_Const)
  {
    IRConst* con = e->Iex.Const.con;
    switch (con->tag)
    {
      case Ico_U1:	l = VG_(sprintf)(s, "0hex%x", con->Ico.U1);
			break;
      case Ico_U8:	l = VG_(sprintf)(s, "0hex%02x", con->Ico.U8);
			break;
      case Ico_U16:	l = VG_(sprintf)(s, "0hex%04x", con->Ico.U16);
			break;
      case Ico_U32:	l = VG_(sprintf)(s, "0hex%08x", con->Ico.U32);
			break;
      case Ico_U64:	l = VG_(sprintf)(s, "0hex%016lx", (HWord) con->Ico.U64);
			break;
      default:		break;
    }
  }
  else
  {
    Char format[256];
    UInt size = curNode->temps[e->Iex.RdTmp.tmp].size;
    VG_(sprintf) (format, "0%s%%%s%dlx", (size == 1) ? "bin" : "hex", (size == 1) ? "" : "0", size >> 2);
/* Changed switch to this */
    l = VG_(sprintf) (s, format, (HWord) value);
  }
  my_write(fdtrace, s, l);
  my_write(fddanger, s, l);
}

static
void translateIRTmp(IRExpr* e)
{
  Char s[256];
  Int l = VG_(sprintf)(s, "t_%llx_%u_%u", curblock, e->Iex.RdTmp.tmp, curvisited);
  my_write(fdtrace, s, l);
  my_write(fddanger, s, l);
}

static
void instrumentIMark(UInt iaddrLowerBytes, UInt iaddrUpperBytes)
{
  Addr64 addr = (((Addr64) iaddrUpperBytes) << 32) ^ iaddrLowerBytes;
  Bool printName = False;
  curIAddr = addr;
  if (dumpCalls)
  {
    if ((printName = getFunctionName(addr, True, False)))
    {
      if (cutAffixes(diFunctionName))
      {
        Char tmp[256];
        VG_(strcpy) (tmp, diFunctionName);
        cutTemplates(tmp);
        if (VG_(HT_lookup) (funcNames, hashCode(tmp)) == NULL)
        {
          Char b[256];
          Char obj[256];
          Bool isStandard = False;
          if (VG_(get_objname) ((Addr)(addr), obj, 256))
          {
            isStandard = isStandardFunction(obj);
          }
          if (!isStandard)
          {
            Int l;
            fnNode* node;
            if (isCPPFunction(diFunctionName))
            {
              l = VG_(sprintf) (b, "$%s\n", diFunctionName);
            }
            else
            { 
              l = VG_(sprintf) (b, "%s\n", diFunctionName);
            }
            my_write(fdfuncFilter, b, l);
            node = VG_(malloc)("fnNode", sizeof(fnNode));
            node->key = hashCode(tmp);
            node->data = NULL;
            VG_(HT_add_node) (funcNames, node);
          }
        }
      }
    }
  }
#ifdef CALL_STACK_PRINTOUT
  if (!dumpCalls)
  {
    printName = getFunctionName(addr, True, False);
  }
  if (printName)
  {
    VG_(printf) ("%s\n", diFunctionName);
  }
#endif
#ifdef TAINTED_TRACE_PRINTOUT
  VG_(printf)("------ IMark(0x%llx) ------\n", addr);
#endif
}

static
void taintMemoryFromFile(HWord key, ULong offset)
{
  Char ss[256];
  Char format[256];
  Int l;
  SizeT s = sizeof(taintedNode);
  taintedNode* node;
  node = VG_(malloc)("taintMemoryNode", s);
  node->key = key;
  //do we really need node->filename field???
  node->filename = curfile;
  node->offset = offset;
  VG_(HT_add_node)(taintedMemory, node);
#if defined(VGA_x86)
  VG_(sprintf)(format, "memory_%d : ARRAY BITVECTOR(32) OF BITVECTOR(8) = memory_%d WITH [0hex%%08x] := file_%s[0hex%%08x];\n", memory + 1, memory, curfile);
#elif defined(VGA_amd64)
  VG_(sprintf)(format, "memory_%d : ARRAY BITVECTOR(64) OF BITVECTOR(8) = memory_%d WITH [0hex%%016lx] := file_%s[0hex%%08x];\n", memory + 1, memory, curfile);
#else
#  error Unknown arch
#endif
  memory++;
  l = VG_(sprintf)(ss, format, key, offset);
  my_write(fdtrace, ss, l);
  my_write(fddanger, ss, l);
}

static
void taintMemoryFromSocket(HWord key, ULong offset)
{
  Char ss[256];
  Char format[256];
  SizeT s = sizeof(taintedNode);
  Int l;
  taintedNode* node;
  node = VG_(malloc)("taintMemoryNode", s);
  node->key = key;
  node->filename = NULL;
  node->offset = offset;
  VG_(HT_add_node)(taintedMemory, node);
#if defined(VGA_x86)
  VG_(sprintf)(format, "memory_%d : ARRAY BITVECTOR(32) OF BITVECTOR(8) = memory_%d WITH [0hex%%08lx] := socket_%d[0hex%%08x];\n", memory + 1, memory, cursocket);
#elif defined(VGA_amd64)
  VG_(sprintf)(format, "memory_%d : ARRAY BITVECTOR(64) OF BITVECTOR(8) = memory_%d WITH [0hex%%016lx] := socket_%d[0hex%%08x];\n", memory + 1, memory, cursocket);
#endif
  memory++;
  l = VG_(sprintf)(ss, format, key, offset);
  my_write(fdtrace, ss, l);
  my_write(fddanger, ss, l);
}

static
void taintMemory(HWord key, UShort size)
{
  taintedNode* node;
  Int i;
/* Changed switch to for */
  for (i = 0; i < (size >> 3); i ++)
  {
    if (VG_(HT_lookup) (taintedMemory, key + i) == NULL)
    {
      node = VG_(malloc)("taintMemoryNode", sizeof(taintedNode));
      node->key = key + i;
      node->filename = NULL;
      VG_(HT_add_node)(taintedMemory, node);
    }
  }
}

static
void untaintMemory(HWord key, UShort size)
{
  taintedNode* node;
  Int i;
/* Changed switch to for */
  for (i = 0; i < (size >> 3); i ++)
  {
    node = VG_(HT_remove) (taintedMemory, key + i);
    if (node != NULL)
    {
      VG_(free) (node);
    }
  }
}

static
void taintRegister(HWord key, UShort size)
{
  taintedNode* node;
  Int i;
/* Changed switch to for */
  for (i = 0; i < (size >> 3); i ++)
  {
    if (VG_(HT_lookup) (taintedRegisters, key + i) == NULL)
    {
      node = VG_(malloc)("taintRegisterNode", sizeof(taintedNode));
      node->key = key + i;
      VG_(HT_add_node)(taintedRegisters, node);
    }
  }
}

static
void untaintRegister(HWord key, UShort size)
{
  taintedNode* node;
  Int i;
/* Changed switch to for */
  for (i = 0; i < (size >> 3); i ++)
  {
    node = VG_(HT_remove) (taintedRegisters, key + i);
    if (node != NULL)
    {
      VG_(free) (node);
    }
  }
}

static
void taintTemp(HWord key)
{
  Char s[256];
  Int l;
  taintedNode* node = VG_(malloc)("taintTempNode", sizeof(taintedNode));
  node->key = key;
  VG_(HT_add_node)(taintedTemps, node);
  l = VG_(sprintf)(s, "t_%llx_%u_%u : BITVECTOR(%u);\n", curblock, (UInt) key, curvisited, curNode->temps[key].size);
  my_write(fdtrace, s, l);
  my_write(fddanger, s, l);
}

static void tg_post_clo_init(void)
{
}

static
void pre_call(ThreadId tid, UInt syscallno)
{
  if (syscallno == __NR_read)
  {
    isRead = True;
  }
  else if (syscallno == __NR_open)
  {
    isOpen = True;
  }
#if defined(VGA_x86)
  else if ((syscallno == __NR_mmap) || (syscallno == __NR_mmap2))
  {
    isMap = True;
  }
#elif defined(VGA_amd64)
  else if (syscallno == __NR_mmap)
  {
    isMap = True;
  }
#endif
}

static
void post_call(ThreadId tid, UInt syscallno, SysRes res)
{
  if (syscallno == __NR_read)
  {
    isRead = False;
  }
  else if ((syscallno == __NR_clone) && !res.isError && (res.res == 0))
  {
    //VG_(printf)("__NR_clone\n");
    //VG_(exit)(0);
  }
  else if (syscallno == __NR_open)
  {
    isOpen = False;
    if ((curfile != NULL) && !curDeclared)
    {
      Char s[256];
      Int l = VG_(sprintf)(s, "file_%s : ARRAY BITVECTOR(32) OF BITVECTOR(8);\n", curfile);
      my_write(fdtrace, s, l);
      my_write(fddanger, s, l);
    }
  }
#if defined(VGA_x86)
  else if ((syscallno == __NR_socketcall) && (accept || connect || socket) && (cursocket != -1))
#elif defined(VGA_amd64)
  else if (((syscallno == __NR_accept) || (syscallno == __NR_connect) || socket) && (cursocket != -1))
#endif
  {
    Char s[256];
    Int l = VG_(sprintf)(s, "socket_%d : ARRAY BITVECTOR(32) OF BITVECTOR(8);\n", cursocket);
    my_write(fdtrace, s, l);
    my_write(fddanger, s, l);
#if defined(VGA_x86)
    accept = False;
    connect = False;
#endif
    socket = False;
  }
#if defined(VGA_x86)
  else if ((syscallno == __NR_mmap) || (syscallno == __NR_mmap2))
#elif defined(VGA_amd64)
  else if (syscallno == __NR_mmap)
#endif
  {
    isMap = False;
  }
}

static
void tg_track_post_mem_write(CorePart part, ThreadId tid, Addr a, SizeT size)
{
  HWord index;
  Int i, oldlength;
  if (isRead && (curfile != NULL) /*&& !checkFParameters*/)
  {
    for (index = a; (index < (a + size)) && (curoffs + (index - a) < cursize); index += 1)
    {
      if (inputFilterEnabled)
      {
        if (VG_(HT_lookup) (inputFilter, curoffs + (index - a)) == NULL)
          taintMemoryFromFile(index, curoffs + (index - a));
      }
      else taintMemoryFromFile(index, curoffs + (index - a));
    }
  }
  else if ((isRead || isRecv) && (sockets || datagrams) && (cursocket != -1))
  {
    if (replace)
    {
      if (cursocket >= socketsNum)
      {
        if (replace_data == NULL)
        {
          replace_data = (replaceData*) VG_(malloc)("replace_data", (cursocket + 1) * sizeof(replaceData));
        }
        else
        {
          replace_data = (replaceData*) VG_(realloc)("replace_data", replace_data, (cursocket + 1) * sizeof(replaceData));
        }
        i = socketsNum;
        for (; i <= cursocket; i++)
        {
          replace_data[i].length = 0;
          replace_data[i].data = NULL;
        }
        socketsNum = cursocket + 1;
      }
      oldlength = replace_data[cursocket].length;
      if (replace_data[cursocket].length < curoffs + size)
      {
        replace_data[cursocket].data = (UChar*) VG_(realloc)("replace_data", replace_data[cursocket].data, curoffs + size);
        VG_(memset)(replace_data[cursocket].data + replace_data[cursocket].length, 0, curoffs + size - replace_data[cursocket].length);
        replace_data[cursocket].length = curoffs + size;
      }
      for (index = a; index < a + size; index++)
      {
        if ((cursocket < socketsBoundary) && (curoffs + (index - a) < oldlength))
        {
          *((UChar*) index) = replace_data[cursocket].data[curoffs + (index - a)];
        }
        else
        {
          replace_data[cursocket].data[curoffs + (index - a)] = *((UChar*) index);
        }
        taintMemoryFromSocket(index, curoffs + (index - a));
      }
    }
    else
    {
      for (index = a; index < a + size; index++)
      {
        taintMemoryFromSocket(index, curoffs + (index - a));
      }
    }
  }
}

static
void tg_track_mem_mmap(Addr a, SizeT size, Bool rr, Bool ww, Bool xx, ULong di_handle)
{
  Addr index = a;
  if (isMap && (curfile != NULL) /*&& !checkFParameters*/)
  {
    for (index = a; (index < (a + size)) && (index < (a + cursize)); index += 1)
    {
      if (inputFilterEnabled)
      {
        if (VG_(HT_lookup) (inputFilter, index - a) == NULL)
          taintMemoryFromFile(index, index - a);
      }
      else taintMemoryFromFile(index, index - a);
    }
  }
}

//unlikely to be ever used
static
void instrumentPutLoad(IRStmt* clone, UInt offset, IRExpr* loadAddr)
{
  UShort size = 0;
  Char ss[256];
  Int l = 0, i;
  HWord addr = (HWord) loadAddr;
  switch (clone->Ist.Put.data->Iex.Load.ty)
  {
    case Ity_I8:	size = 8;
			break;
    case Ity_I16:	size = 16;
			break;
    case Ity_I32:	size = 32;
			break;
    case Ity_I64:	size = 64;
			break;
    default:		return;
                        break;
  }
  if (VG_(HT_lookup)(taintedMemory, (HWord) loadAddr) != NULL)
  {
    taintRegister(offset, size);
#ifdef TAINTED_TRACE_PRINTOUT
    ppIRStmt(clone);
    VG_(printf) ("\n");
#endif
#ifdef TAINTED_BLOCKS_PRINTOUT
    if(newSB)
    {
      ppIRSB(printSB);
      VG_(printf) ("\n");
      newSB = False;
    }
#endif

/* Changed switch to for. */
    for (i = 0; i < (size >> 3); i ++)
    {
#if defined(VGA_x86)
      l = VG_(sprintf) (ss, "registers_%d : ARRAY BITVECTOR(8) OF BITVECTOR(8) = registers_%d WITH [0hex%02x] := memory_%d[0hex%08x];\n", 
                        registers + 1 + i, registers + i, offset + i, memory, (UInt) (addr + i));
#elif defined(VGA_amd64)
      l = VG_(sprintf) (ss, "registers_%d : ARRAY BITVECTOR(8) OF BITVECTOR(8) = registers_%d WITH [0hex%02x] := memory_%d[0hex%016lx];\n", 
                        registers + 1 + i, registers + i, offset + i, memory, (HWord) (addr + i));
#endif
      my_write(fdtrace, ss, l);
      my_write(fddanger, ss, l);
    }
    registers += i;
  }
  else
  {
    untaintRegister(offset, size);
  }
}

//unlikely to be ever used
static
void instrumentPutGet(IRStmt* clone, UInt putOffset, UInt getOffset)
{
  UShort size = 0;
  Char ss[256];
  Int l = 0, i;
  switch (clone->Ist.Put.data->Iex.Get.ty)
  {
    case Ity_I8:	size = 8;
			break;
    case Ity_I16:	size = 16;
			break;
    case Ity_I32:	size = 32;
			break;
    case Ity_I64:	size = 64;
			break;
    default:		return;
                        break;
  }
  if (VG_(HT_lookup)(taintedRegisters, getOffset) != NULL)
  {
    taintRegister(putOffset, size);
#ifdef TAINTED_TRACE_PRINTOUT
    ppIRStmt(clone);
    VG_(printf) ("\n");
#endif
#ifdef TAINTED_BLOCKS_PRINTOUT
    if(newSB)
    {
      ppIRSB(printSB);
      VG_(printf) ("\n");
      newSB = False;
    }
#endif

/* Changed switch to for. */
    for (i = 0; i < (size >> 3); i ++)
    {
      l = VG_(sprintf) (ss, "registers_%d : ARRAY BITVECTOR(8) OF BITVECTOR(8) = registers_%d WITH [0hex%02x] := registers_%d[0hex%02x];\n", 
                        registers + 1 + i, registers + i, putOffset + i, registers + i, getOffset + i);
      my_write(fdtrace, ss, l);
      my_write(fddanger, ss, l);
    }
    registers += i;
  }
  else
  {
    untaintRegister(putOffset, size);
  }
}

static
void instrumentPutRdTmp(IRStmt* clone, UInt offset, UInt tmp)
{
  if (VG_(HT_lookup)(taintedTemps, tmp) != NULL)
  {
    Char ss[256];
    Int l = 0, size = curNode->temps[tmp].size;
    Int i;
    taintRegister(offset, curNode->temps[tmp].size);
#ifdef TAINTED_TRACE_PRINTOUT
    ppIRStmt(clone);
    VG_(printf) ("\n");
#endif
#ifdef TAINTED_BLOCKS_PRINTOUT
    if(newSB)
    {
      ppIRSB(printSB);
      VG_(printf) ("\n");
      newSB = False;
    }
#endif
/* Changed switch to this */
    if (size == 8)
    {
      l = VG_(sprintf)(ss, "registers_%d : ARRAY BITVECTOR(8) OF BITVECTOR(8) = registers_%d WITH [0hex%02x] := t_%llx_%u_%u;\n", 
                       registers + 1, registers, offset, curblock, tmp, curvisited);
      my_write(fdtrace, ss, l);
      my_write(fddanger, ss, l);
      registers++;
    }
    else
    {
      for (i = 0; i < (size >> 3); i ++)
      {
        l = VG_(sprintf) (ss, "registers_%d : ARRAY BITVECTOR(8) OF BITVECTOR(8) = registers_%d WITH [0hex%02x] := t_%llx_%u_%u[%d:%d];\n", 
                          registers + 1 + i, registers + i, offset + i, curblock, tmp, curvisited, ((i + 1) << 3) - 1, i << 3);
        my_write(fdtrace, ss, l);
        my_write(fddanger, ss, l);
      }
      registers += i;
    }
  }
  else
  {
    untaintRegister(offset, curNode->temps[tmp].size);
  }
}

static
void instrumentPutConst(IRStmt* clone, UInt offset)
{
  switch (clone->Ist.Put.data->Iex.Const.con->tag)
  {
    case Ico_U8:	untaintRegister(offset, 8);
			break;
    case Ico_U16:	untaintRegister(offset, 16);
			break;
    case Ico_U32:	untaintRegister(offset, 32);
 			break;
    case Ico_U64:	untaintRegister(offset, 64);
 			break;
    default:		break;
  }
  if (VG_(HT_lookup)(taintedRegisters, offset) != NULL)
  {
#ifdef TAINTED_TRACE_PRINTOUT
    ppIRStmt(clone);
    VG_(printf) ("\n");
#endif
#ifdef TAINTED_BLOCKS_PRINTOUT
    if(newSB)
    {
      ppIRSB(printSB);
      VG_(printf) ("\n");
      newSB = False;
    }
#endif
  }
}

static
void instrumentWrTmpLoad(IRStmt* clone, UInt tmp, IRExpr* loadAddr, IRType ty, UInt rtmp)
{
  taintedNode* t = VG_(HT_lookup)(taintedMemory, (HWord) loadAddr);
  HWord addr = (HWord) loadAddr;

/* Stuff for catching formal params. I'll leave it in order not
   to lose. */
  
/* TODO: check what's happening when params have const modifier */

  /*if (checkFParameters && useFiltering())
  {
    Char curLocFile[256];
    Char* loadLocFile;
    Char* loadLocLine;
    Char* funcLoc;
    Int curLocLine;
    Char n1[256];
    Char n2[256];
    Bool hasLoc = False;
    getFunctionName(curIAddr, False, True);
    funcLoc = VG_(strchr) (diFunctionName, '+');
    if (funcLoc != NULL)
    {
      funcLoc ++;
      hasLoc = VG_(get_filename_linenum) (curIAddr - (Addr)VG_(strtoll10) (funcLoc, NULL), curLocFile, 256, NULL, 0, NULL, &curLocLine);
    }
    VG_(get_local_data_description) (n1, n2, 256, (Addr)loadAddr);
    if (VG_(strstr) (n1, "formal param") != NULL && (loadLocFile = VG_(strstr) (n2, "declared at ")) != NULL)
    {
#define DECLARED_AT__LENGTH 12
      loadLocFile += DECLARED_AT__LENGTH;
#undef DECLARED_AT__LENGTH
      loadLocLine = VG_(strchr) (loadLocFile, ':');
      if (loadLocLine != NULL)
      {
        *loadLocLine = '\0';
        if (VG_(strcmp) (curLocFile, loadLocFile) == 0)
        {
          if (VG_(strtoll10) (loadLocLine + 1, NULL) < curLocLine)
          {
            if (hasLoc) VG_(printf) ("current location: %s %d\n",curLocFile, curLocLine);
            VG_(printf) ("%s %s\n", n1, n2);
            VG_(printf) ("size is %d, value is %d\n", curNode->temps[tmp].size, *((Int *)loadAddr));
            encounteredFP = True;
            taintMemory((HWord) loadAddr, curNode->temps[tmp].size);
            taintTemp(rtmp);
          }
        }
      }
    }
  }*/
#if defined(CUT_ASSERT_WITH_QUERY)
  if (VG_(HT_lookup)(taintedTemps, rtmp) != NULL && (!filterDangerous || useFiltering()))
  {
#else
  if (VG_(HT_lookup)(taintedTemps, rtmp) != NULL)
  {
#endif
    Char s[256];
    Int l = 0;
    Addr addrs[256];
    Char format[256];
    const NSegment* seg;
    VG_(am_get_client_segment_starts)(addrs, 256);
    seg = VG_(am_find_nsegment)(addrs[0]);
#if defined(CUT_ASSERT_WITH_QUERY)
    VG_(sprintf)(format, "ASSERT(BVLT(t_%%llx_%%u_%%u, 0hex%%0%ux));\nQUERY(FALSE)\n",
                 curNode->temps[rtmp].size / 4);
#else
    if (!filterDangerous || useFiltering())
    {
      VG_(sprintf)(format, "ASSERT(BVLT(t_%%llx_%%u_%%u, 0hex%%0%ux));\nQUERY(FALSE)\n",
                   curNode->temps[rtmp].size / 4);
    }
    else
    {
      VG_(sprintf)(format, "ASSERT(BVLT(t_%%llx_%%u_%%u, 0hex%%0%ux));\n",
                   curNode->temps[rtmp].size / 4);
    }
#endif
    l = VG_(sprintf)(s, format, curblock, rtmp, curvisited, seg->start);
    my_write(fddanger, s, l);

  }
  if (t != NULL)
  {
    Char s[1024];
    Int l = 0;
    taintTemp(tmp);
#ifdef TAINTED_TRACE_PRINTOUT
    ppIRStmt(clone);
    VG_(printf) ("\n");
#endif
#ifdef TAINTED_BLOCKS_PRINTOUT
    if(newSB)
    {
      ppIRSB(printSB);
      VG_(printf) ("\n");
      newSB = False;
    }
#endif
    switch (curNode->temps[tmp].size)
    {
#if defined(VGA_x86)
      case 8:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=memory_%d[0hex%08x]);\n", curblock, tmp, curvisited, memory, (UInt) addr);
		break;
      case 16:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=((memory_%d[0hex%08x] @ 0hex00) | (0hex00 @ memory_%d[0hex%08x])));\n", 
                                 curblock, tmp, curvisited, memory, (UInt) (addr + 1), memory, (UInt) addr);
		break;
      case 32:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=((memory_%d[0hex%08x] @ 0hex000000) | (0hex00 @ memory_%d[0hex%08x] @ 0hex0000) | (0hex0000 @ memory_%d[0hex%08x] @ 0hex00) | (0hex000000 @ memory_%d[0hex%08x])));\n", 
                                 curblock, tmp, curvisited, memory, (UInt) (addr + 3), memory, 
                                                                    (UInt) (addr + 2), memory, 
                                                                    (UInt) (addr + 1), memory, (UInt) addr);
		break;
#elif defined(VGA_amd64)
      case 8:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=memory_%d[0hex%016lx]);\n", curblock, tmp, curvisited, memory, addr);
		break;
      case 16:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=((memory_%d[0hex%016lx] @ 0hex00) | (0hex00 @ memory_%d[0hex%016lx])));\n", 
                                 curblock, tmp, curvisited, memory, addr + 1, memory, addr);
		break;
      case 32:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=((memory_%d[0hex%016lx] @ 0hex000000) | (0hex00 @ memory_%d[0hex%016lx] @ 0hex0000) | (0hex0000 @ memory_%d[0hex%016lx] @ 0hex00) | (0hex000000 @ memory_%d[0hex%016lx])));\n", 
                                 curblock, tmp, curvisited, memory, addr + 3, memory, addr + 2, memory, addr + 1, memory, addr);
		break;
      case 64:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=((memory_%d[0hex%016lx] @ 0hex00000000000000) | (0hex00 @ memory_%d[0hex%016lx] @ 0hex000000000000) | (0hex0000 @ memory_%d[0hex%016lx] @ 0hex0000000000) | (0hex000000 @ memory_%d[0hex%016lx] @ 0hex00000000) | (0hex00000000 @ memory_%d[0hex%016lx] @ 0hex000000) | (0hex0000000000 @ memory_%d[0hex%016lx] @ 0hex0000) | (0hex000000000000 @ memory_%d[0hex%016lx] @ 0hex00) | (0hex00000000000000 @ memory_%d[0hex%016lx])));\n", 
                                 curblock, tmp, curvisited, memory, addr + 7, memory, addr + 6, 
                                                            memory, addr + 5, memory, addr + 4, 
                                                            memory, addr + 3, memory, addr + 2, 
                                                            memory, addr + 1, memory, addr);
		break;
#endif
    }
    my_write(fdtrace, s, l);
    my_write(fddanger, s, l);
  }
}

static
void instrumentWrTmpGet(IRStmt* clone, UInt tmp, UInt offset)
{
  if (VG_(HT_lookup)(taintedRegisters, offset) != NULL)
  {
    Char s[1024];
    Int l = 0;
    taintTemp(tmp);
    switch (curNode->temps[tmp].size)
    {
      case 8:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=registers_%d[0hex%02x]);\n", curblock, tmp, curvisited, registers, offset);
                break;
      case 16:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=((0hex00 @ registers_%d[0hex%02x]) | (registers_%d[0hex%02x] @ 0hex00)));\n", 
                                 curblock, tmp, curvisited, registers, offset, registers, offset + 1);
		break;
      case 32:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=((0hex000000 @ registers_%d[0hex%02x]) | (0hex0000 @ registers_%d[0hex%02x] @ 0hex00) | (0hex00 @ registers_%d[0hex%02x] @ 0hex0000) | (registers_%d[0hex%02x] @ 0hex000000)));\n", 
                                 curblock, tmp, curvisited, registers, offset, registers, offset + 1, registers, offset + 2, registers, offset + 3);
		break;
      case 64:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=((0hex00000000000000 @ registers_%d[0hex%02x]) | (0hex000000000000 @ registers_%d[0hex%02x] @ 0hex00) | (0hex0000000000 @ registers_%d[0hex%02x] @ 0hex0000) | (0hex00000000 @ registers_%d[0hex%02x] @ 0hex000000) | (0hex000000 @ registers_%d[0hex%02x] @ 0hex00000000) | (0hex0000 @ registers_%d[0hex%02x] @ 0hex0000000000) | (0hex00 @ registers_%d[0hex%02x] @ 0hex000000000000) | (registers_%d[0hex%02x] @ 0hex00000000000000)));\n", 
                                 curblock, tmp, curvisited, registers, offset, registers, offset + 1, registers, offset + 2, registers, offset + 3, 
                                                            registers, offset + 4, registers, offset + 5, registers, offset + 6, registers, offset + 7);
		break;
      default:	break;
    }
    my_write(fdtrace, s, l);
    my_write(fddanger, s, l);
#ifdef TAINTED_TRACE_PRINTOUT
    ppIRStmt(clone);
    VG_(printf) ("\n");
#endif
#ifdef TAINTED_BLOCKS_PRINTOUT
    if(newSB)
    {
      ppIRSB(printSB);
      VG_(printf) ("\n");
      newSB = False;
    }
#endif
  }
}

static
void instrumentWrTmpRdTmp(IRStmt* clone, UInt ltmp, UInt rtmp)
{
  if (VG_(HT_lookup)(taintedTemps, rtmp) != NULL)
  {
    Int l;
    Char s[256];
    taintTemp(ltmp);
#ifdef TAINTED_TRACE_PRINTOUT
    ppIRStmt(clone);
    VG_(printf) ("\n");
#endif
#ifdef TAINTED_BLOCKS_PRINTOUT
    if(newSB)
    {
      ppIRSB(printSB);
      VG_(printf) ("\n");
      newSB = False;
    }
#endif
    l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=t_%llx_%u_%u);\n", curblock, ltmp, curvisited, curblock, rtmp, curvisited);
    my_write(fdtrace, s, l);
    my_write(fddanger, s, l);
  }
}

static
void instrumentWrTmpUnop(IRStmt* clone, UInt ltmp, UInt rtmp, IROp op)
{
  if (VG_(HT_lookup)(taintedTemps, rtmp) != NULL)
  {
    Char s[256];
    Int l = 0;
    taintTemp(ltmp);
#ifdef TAINTED_TRACE_PRINTOUT
    ppIRStmt(clone);
    VG_(printf) ("\n");
#endif
#ifdef TAINTED_BLOCKS_PRINTOUT
    if(newSB)
    {
      ppIRSB(printSB);
      VG_(printf) ("\n");
      newSB = False;
    }
#endif
    switch (op)
    {
      case Iop_1Uto8:   l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=0bin0000000@t_%llx_%u_%u);\n", curblock, ltmp, curvisited, curblock, rtmp, curvisited);
			break;
      case Iop_1Uto32:  l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=0bin0000000000000000000000000000000@t_%llx_%u_%u);\n", curblock, ltmp, curvisited, curblock, rtmp, curvisited);
			break;
      case Iop_1Uto64:  l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=0bin000000000000000000000000000000000000000000000000000000000000000@t_%llx_%u_%u);\n", curblock, ltmp, curvisited, curblock, rtmp, curvisited);
			break;
      case Iop_8Uto16:  l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=0hex00@t_%llx_%u_%u);\n", curblock, ltmp, curvisited, curblock, rtmp, curvisited);
			break;
      case Iop_8Uto32:  l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=0hex000000@t_%llx_%u_%u);\n", curblock, ltmp, curvisited, curblock, rtmp, curvisited);
			break;
      case Iop_8Uto64:  l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=0hex00000000000000@t_%llx_%u_%u);\n", curblock, ltmp, curvisited, curblock, rtmp, curvisited);
			break;
      case Iop_16Uto32: l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=0hex0000@t_%llx_%u_%u);\n", curblock, ltmp, curvisited, curblock, rtmp, curvisited);
			break;
      case Iop_16Uto64: l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=0hex000000000000@t_%llx_%u_%u);\n", curblock, ltmp, curvisited, curblock, rtmp, curvisited);
			break;
      case Iop_32Uto64: l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=0hex00000000@t_%llx_%u_%u);\n", curblock, ltmp, curvisited, curblock, rtmp, curvisited);
			break;

      case Iop_1Sto8:  	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=BVSX(t_%llx_%u_%u, 8));\n", curblock, ltmp, curvisited, curblock, rtmp, curvisited);
			break;
      case Iop_1Sto16: 	
      case Iop_8Sto16:  l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=BVSX(t_%llx_%u_%u, 16));\n", curblock, ltmp, curvisited, curblock, rtmp, curvisited);
			break;
      case Iop_1Sto32:
      case Iop_8Sto32:
      case Iop_16Sto32: l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=BVSX(t_%llx_%u_%u, 32));\n", curblock, ltmp, curvisited, curblock, rtmp, curvisited);
			break;
      case Iop_1Sto64:
      case Iop_8Sto64:
      case Iop_16Sto64:
      case Iop_32Sto64: l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=BVSX(t_%llx_%u_%u, 64));\n", curblock, ltmp, curvisited, curblock, rtmp, curvisited);
			break;

      case Iop_16to8:
      case Iop_32to8:
      case Iop_64to8:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=t_%llx_%u_%u[7:0]);\n", curblock, ltmp, curvisited, curblock, rtmp, curvisited);
			break;
      case Iop_32to16:
      case Iop_64to16:
			l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=t_%llx_%u_%u[15:0]);\n", curblock, ltmp, curvisited, curblock, rtmp, curvisited);
			break;
      case Iop_64to32:
			l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=t_%llx_%u_%u[31:0]);\n", curblock, ltmp, curvisited, curblock, rtmp, curvisited);
			break;
      case Iop_32to1:
      case Iop_64to1:
			l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=t_%llx_%u_%u[0:0]);\n", curblock, ltmp, curvisited, curblock, rtmp, curvisited);
			break;
      case Iop_16HIto8:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=t_%llx_%u_%u[15:8]);\n", curblock, ltmp, curvisited, curblock, rtmp, curvisited);
			break;
      case Iop_32HIto16:l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=t_%llx_%u_%u[31:16]);\n", curblock, ltmp, curvisited, curblock, rtmp, curvisited);
			break;
      case Iop_64HIto32:l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=t_%llx_%u_%u[63:32]);\n", curblock, ltmp, curvisited, curblock, rtmp, curvisited);
			break;


      case Iop_Not1:
      case Iop_Not8:
      case Iop_Not16:
      case Iop_Not32:
      case Iop_Not64:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=~t_%llx_%u_%u);\n", curblock, ltmp, curvisited, curblock, rtmp, curvisited);
			break;
      default:		break;
    }
    my_write(fdtrace, s, l);
    my_write(fddanger, s, l);
  }
}

static
UShort isPropagation2(IRExpr* arg1, IRExpr* arg2)
{
  if ((arg1->tag == Iex_RdTmp) && (arg2->tag != Iex_RdTmp))
  {
    return (VG_(HT_lookup)(taintedTemps, arg1->Iex.RdTmp.tmp) != NULL) ? 1 : 0;
  }
  else if ((arg1->tag != Iex_RdTmp) && (arg2->tag == Iex_RdTmp))
  {
    UShort b2 = (VG_(HT_lookup)(taintedTemps, arg2->Iex.RdTmp.tmp) != NULL) ? 1 : 0;
    return b2 << 1;
  }
  else if ((arg1->tag == Iex_RdTmp) && (arg2->tag == Iex_RdTmp))
  {
    UShort b1 = (VG_(HT_lookup)(taintedTemps, arg1->Iex.RdTmp.tmp) != NULL) ? 1 : 0;
    UShort b2 = (VG_(HT_lookup)(taintedTemps, arg2->Iex.RdTmp.tmp) != NULL) ? 1 : 0;
    return (b2 << 1) ^ b1;
  }
  else
  {
    return 0;
  }
}

static
Bool firstTainted(UShort res)
{
  return res & 0x1;
}

static
Bool secondTainted(UShort res)
{
  return res & 0x2;
}

static
void translateLong1(IRExpr* arg, Addr64 value, UShort taintedness)
{
  if (firstTainted(taintedness))
  {
    translateIRTmp(arg);
  }
  else
  {
    translateLongValue(arg, value);
  }
}

static
void translateLong2(IRExpr* arg, Addr64 value, UShort taintedness)
{
  if (secondTainted(taintedness))
  {
    translateIRTmp(arg);
  }
  else
  {
    translateLongValue(arg, value);
  }
}

static
void translate1(IRExpr* arg, IRExpr* value, UShort taintedness)
{
  if (firstTainted(taintedness))
  {
    translateIRTmp(arg);
  }
  else
  {
    translateValue(arg, value);
  }
}

static
void translate2(IRExpr* arg, IRExpr* value, UShort taintedness)
{
  if (secondTainted(taintedness))
  {
    translateIRTmp(arg);
  }
  else
  {
    translateValue(arg, value);
  }
}

static
void printSizedTrue(UInt ltmp, Int fd)
{
  Char s[256];
  Int l = 0;
  switch (curNode->temps[ltmp].size)
  {
    case 1:	l = VG_(sprintf)(s, "0bin1");
		break;
    case 8:	l = VG_(sprintf)(s, "0hex01");
		break;
    case 16:	l = VG_(sprintf)(s, "0hex0001");
		break;
    case 32:	l = VG_(sprintf)(s, "0hex00000001");
		break;
    case 64:	l = VG_(sprintf)(s, "0hex0000000000000001");
		break;
    default:	break;
  }
  my_write(fd, s, l);
}

static
void printSizedFalse(UInt ltmp, Int fd)
{
  Char s[256];
  Int l = 0;
  switch (curNode->temps[ltmp].size)
  {
    case 1:	l = VG_(sprintf)(s, "0bin0");
		break;
    case 8:	l = VG_(sprintf)(s, "0hex00");
		break;
    case 16:	l = VG_(sprintf)(s, "0hex0000");
		break;
    case 32:	l = VG_(sprintf)(s, "0hex00000000");
		break;
    case 64:	l = VG_(sprintf)(s, "0hex0000000000000000");
		break;
    default:	break;
  }
  my_write(fd, s, l);
}

static
void instrumentWrTmpCCall(IRStmt* clone, IRExpr* arg1, IRExpr* arg2, HWord size, IRExpr* value1, IRExpr* value2)
{
  UShort r = isPropagation2(arg1, arg2);
  UInt op = clone->Ist.WrTmp.data->Iex.CCall.args[0]->Iex.Const.con->Ico.U32;
  UInt ltmp = clone->Ist.WrTmp.tmp;
  Bool noWrite = False;
  if (r)
  {
    Char s[256];
    Int l = 0;
    taintTemp(ltmp);
#ifdef TAINTED_TRACE_PRINTOUT
    ppIRStmt(clone);
    VG_(printf) ("\n");
#endif
#ifdef TAINTED_BLOCKS_PRINTOUT
    if(newSB)
    {
      ppIRSB(printSB);
      VG_(printf) ("\n");
      newSB = False;
    }
#endif
#if defined(VGA_x86)
    size %= 3;
#elif defined(VGA_amd64)
    size %= 4;
#endif
    switch (op)
    {
      case X86CondB:    l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=IF BVLT(", curblock, ltmp, curvisited);
                        break;
      case X86CondNB:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=IF BVGE(", curblock, ltmp, curvisited);
                        break;
      case X86CondZ:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=IF ", curblock, ltmp, curvisited);
                        break;
      case X86CondNZ:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=IF NOT(", curblock, ltmp, curvisited);
                        break;
      case X86CondBE:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=IF BVLE(", curblock, ltmp, curvisited);
                        break;
      case X86CondNBE:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=IF BVGT(", curblock, ltmp, curvisited);
                        break;
      case X86CondL:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=IF SBVLT(", curblock, ltmp, curvisited);
                        break;
      case X86CondNL:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=IF SBVGE(", curblock, ltmp, curvisited);
                        break;
      case X86CondLE:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=IF SBVLE(", curblock, ltmp, curvisited);
                        break;
      case X86CondNLE:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=IF SBVGT(", curblock, ltmp, curvisited);
                        break;
      default:          noWrite = True; break;
    }
    if (!noWrite)
    {
      my_write(fdtrace, s, l);
      my_write(fddanger, s, l);
      translate1(arg1, value1, r);
#if defined(VGA_x86)
      if (size == 0)
      {
        l = VG_(sprintf)(s, "[31:0],");
      }
#elif defined(VGA_amd64)
      if (size == 0)
      {
        l = VG_(sprintf)(s, "[63:0],");
      }
      else if (size == 3)
      {
        l = VG_(sprintf)(s, "[31:0],");
      }
#endif
      else if (size == 1)
      {
        l = VG_(sprintf)(s, "[7:0],");
      }
      else if (size == 2)
      {
        l = VG_(sprintf)(s, "[15:0],");
      }
      my_write(fdtrace, s, l);
      my_write(fddanger, s, l);
      translate2(arg2, value2, r);
#if defined(VGA_x86)
      if (size == 0)
      {
        l = VG_(sprintf)(s, "[31:0]) THEN ");
      }
#elif defined(VGA_amd64)
      if (size == 0)
      {
        l = VG_(sprintf)(s, "[63:0]) THEN ");
      }
      else if (size == 3)
      {
        l = VG_(sprintf)(s, "[31:0]) THEN ");
      }
#endif
      else if (size == 1)
      {
        l = VG_(sprintf)(s, "[7:0]) THEN ");
      }
      else if (size == 2)
      {
        l = VG_(sprintf)(s, "[15:0]) THEN ");
      }
      my_write(fdtrace, s, l);
      my_write(fddanger, s, l);
      printSizedTrue(ltmp, fdtrace);
      printSizedTrue(ltmp, fddanger);
      l = VG_(sprintf)(s, " ELSE ");
      my_write(fdtrace, s, l);
      my_write(fddanger, s, l);
      printSizedFalse(ltmp, fdtrace);
      printSizedFalse(ltmp, fddanger);
      l = VG_(sprintf)(s, " ENDIF);\n");
      my_write(fdtrace, s, l);
      my_write(fddanger, s, l);
    }
  }
}

/* I'm changing this too (see comments in instrumentWrTmp) */

/*
#if defined(VGA_x86)
static
void instrumentWrTmpLongBinop(IRStmt* clone, UInt oprt, UInt ltmp, IRExpr* arg1, IRExpr* arg2, UInt value1LowerBytes, UInt value1UpperBytes, UInt value2LowerBytes, UInt value2UpperBytes)
{
  UShort r = isPropagation2(arg1, arg2);
  if (r)
  {
    Addr64 value1 = (((Addr64) value1UpperBytes) << 32) ^ value1LowerBytes;
    Addr64 value2 = (((Addr64) value2UpperBytes) << 32) ^ value2LowerBytes;
#elif defined(VGA_amd64)
*/

static
void instrumentWrTmpLongBinop(IRStmt* clone, IRExpr* arg1, IRExpr* arg2, HWord value1, HWord value2)
{
  UInt ltmp = clone->Ist.WrTmp.tmp;
  UInt oprt = clone->Ist.WrTmp.data->Iex.Binop.op;
  UShort r = isPropagation2(arg1, arg2);
  if (r)
  {
//#endif
    Char s[256];
    Int l = 0;
    taintTemp(ltmp);
#ifdef TAINTED_TRACE_PRINTOUT
    ppIRStmt(clone);
    VG_(printf) ("\n");
#endif
#ifdef TAINTED_BLOCKS_PRINTOUT
    if(newSB)
    {
      ppIRSB(printSB);
      VG_(printf) ("\n");
      newSB = False;
    }
#endif
    switch (oprt)
    {
      case Iop_CmpEQ64:		l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=IF ", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    			 	translateLong1(arg1, value1, r);
    				l = VG_(sprintf)(s, "=");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    				translateLong2(arg2, value2, r);
    				l = VG_(sprintf)(s, " THEN ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
      				printSizedTrue(ltmp, fdtrace);
      				printSizedTrue(ltmp, fddanger);
				l = VG_(sprintf)(s, " ELSE ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
                                printSizedFalse(ltmp, fdtrace);
      				printSizedFalse(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ENDIF);\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_CmpLT64S:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=IF SBVLT(", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    			 	translateLong1(arg1, value1, r);
    				l = VG_(sprintf)(s, ", ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    				translateLong2(arg2, value2, r);
    				l = VG_(sprintf)(s, ") THEN ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
      				printSizedTrue(ltmp, fdtrace);
      				printSizedTrue(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ELSE ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
                                printSizedFalse(ltmp, fdtrace);
      				printSizedFalse(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ENDIF);\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_CmpLT64U:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=IF BVLT(", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    			 	translateLong1(arg1, value1, r);
    				l = VG_(sprintf)(s, ", ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    				translateLong2(arg2, value2, r);
    				l = VG_(sprintf)(s, ") THEN ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
      				printSizedTrue(ltmp, fdtrace);
      				printSizedTrue(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ELSE ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
                                printSizedFalse(ltmp, fdtrace);
      				printSizedFalse(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ENDIF);\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_CmpLE64S:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=IF SBVLE(", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    			 	translateLong1(arg1, value1, r);
    				l = VG_(sprintf)(s, ", ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    				translateLong2(arg2, value2, r);
    				l = VG_(sprintf)(s, ") THEN ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
      				printSizedTrue(ltmp, fdtrace);
      				printSizedTrue(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ELSE ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
                                printSizedFalse(ltmp, fdtrace);
      				printSizedFalse(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ENDIF);\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_CmpLE64U:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=IF BVLE(", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    			 	translateLong1(arg1, value1, r);
    				l = VG_(sprintf)(s, ", ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    				translateLong2(arg2, value2, r);
    				l = VG_(sprintf)(s, ") THEN ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
      				printSizedTrue(ltmp, fdtrace);
      				printSizedTrue(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ELSE ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
                                printSizedFalse(ltmp, fdtrace);
      				printSizedFalse(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ENDIF);\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_CmpNE64:		l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=IF NOT(", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    			 	translateLong1(arg1, value1, r);
    				l = VG_(sprintf)(s, "=");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    				translateLong2(arg2, value2, r);
    				l = VG_(sprintf)(s, ") THEN ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
      				printSizedTrue(ltmp, fdtrace);
      				printSizedTrue(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ELSE ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
                                printSizedFalse(ltmp, fdtrace);
      				printSizedFalse(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ENDIF);\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_Add64:		l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=BVPLUS(64,", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateLong1(arg1, value1, r);
				l = VG_(sprintf)(s, ",");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateLong2(arg2, value2, r);
				l = VG_(sprintf)(s, "));\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_Sub64: 		l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=BVSUB(64,", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateLong1(arg1, value1, r);
				l = VG_(sprintf)(s, ",");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateLong2(arg2, value2, r);
				l = VG_(sprintf)(s, "));\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_Mul64: 		l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=BVMULT(64,", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateLong1(arg1, value1, r);
				l = VG_(sprintf)(s, ",");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateLong2(arg2, value2, r);
				l = VG_(sprintf)(s, "));\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_Or64: 		l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateLong1(arg1, value1, r);
				l = VG_(sprintf)(s, "|");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateLong2(arg2, value2, r);
				l = VG_(sprintf)(s, ");\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_And64: 		l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateLong1(arg1, value1, r);
				l = VG_(sprintf)(s, "&");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateLong2(arg2, value2, r);
				l = VG_(sprintf)(s, ");\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_Xor64: 		l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=BVXOR(", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateLong1(arg1, value1, r);
				l = VG_(sprintf)(s, ",");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateLong2(arg2, value2, r);
				l = VG_(sprintf)(s, "));\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_Sar64:		if (secondTainted(r))
				{
				  //break;
				}
				l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=SBVDIV(64,", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateLong1(arg1, value1, r);
				l = VG_(sprintf)(s, ",");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateLongToPowerOfTwo(arg2, value2);
				l = VG_(sprintf)(s, "));\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_Shl64: 		if (secondTainted(r))
				{
				  //break;
				}
                                value2 = getLongDecimalValue(arg2, value2);
				if (value2 == 0)
                                {
                                  l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=", curblock, ltmp, curvisited);
				  my_write(fdtrace, s, l);
				  my_write(fddanger, s, l);
                                  translateLong1(arg1, value1, r);
                                  l = VG_(sprintf)(s, ");\n");
				  my_write(fdtrace, s, l);
				  my_write(fddanger, s, l);
                                }
                                else
                                {
				  l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=(", curblock, ltmp, curvisited);
				  my_write(fdtrace, s, l);
				  my_write(fddanger, s, l);
				  translateLong1(arg1, value1, r);
				  l = VG_(sprintf)(s, " << %llu)[63:0]);\n", (ULong) value2);
				  my_write(fdtrace, s, l);
				  my_write(fddanger, s, l);
				}
				break;
      case Iop_Shr64: 		if (secondTainted(r))
				{
				  //break;
				}
                                value2 = getLongDecimalValue(arg2, value2);
				if (value2 == 0)
                                {
                                  l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=", curblock, ltmp, curvisited);
				  my_write(fdtrace, s, l);
				  my_write(fddanger, s, l);
                                  translateLong1(arg1, value1, r);
                                  l = VG_(sprintf)(s, ");\n");
				  my_write(fdtrace, s, l);
				  my_write(fddanger, s, l);
                                }
                                else
                                {
				  l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=(", curblock, ltmp, curvisited);
				  my_write(fdtrace, s, l);
				  my_write(fddanger, s, l);
				  translateLong1(arg1, value1, r);
				  l = VG_(sprintf)(s, ">> %llu));\n", (ULong) value2);
				  my_write(fdtrace, s, l);
				  my_write(fddanger, s, l);
				}
				break;
#if defined(CUT_ASSERT_WITH_QUERY)
      case Iop_DivU64:		if ((arg2->tag == Iex_RdTmp) && secondTainted(r) && (!filterDangerous || useFiltering()))
#else
      case Iop_DivU64:		if ((arg2->tag == Iex_RdTmp) && secondTainted(r))
#endif
				{
				  l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=", curblock, arg2->Iex.RdTmp.tmp, curvisited);
				  my_write(fddanger, s, l);
				  printSizedFalse(arg2->Iex.RdTmp.tmp, fddanger);
#if defined(CUT_ASSERT_WITH_QUERY)
				  l = VG_(sprintf)(s, ");\nQUERY(FALSE);\n");
#else
				  if (!filterDangerous || useFiltering())
				  {
				    l = VG_(sprintf)(s, ");\nQUERY(FALSE);\n");
				  }
				  else
				  {
				    l = VG_(sprintf)(s, ");\n");
                                  }
#endif
				  my_write(fddanger, s, l);
				}
				l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=BVDIV(64,", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateLong1(arg1, value1, r);
				l = VG_(sprintf)(s, ",");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateLong2(arg2, value2, r);
				l = VG_(sprintf)(s, "));\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
#if defined(CUT_ASSERT_WITH_QUERY)
      case Iop_DivS64:		if ((arg2->tag == Iex_RdTmp) && secondTainted(r) && (!filterDangerous || useFiltering()))
#else
      case Iop_DivS64:		if ((arg2->tag == Iex_RdTmp) && secondTainted(r))
#endif
				{
				  l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=", curblock, arg2->Iex.RdTmp.tmp, curvisited);
				  my_write(fddanger, s, l);
				  printSizedFalse(arg2->Iex.RdTmp.tmp, fddanger);
#if defined(CUT_ASSERT_WITH_QUERY)
				  l = VG_(sprintf)(s, ");\nQUERY(FALSE);\n");
#else
				  if (!filterDangerous || useFiltering())
				  {
				    l = VG_(sprintf)(s, ");\nQUERY(FALSE);\n");
				  }
				  else
				  {
				    l = VG_(sprintf)(s, ");\n");
                                  }
#endif
				  my_write(fddanger, s, l);
				}
				l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=SBVDIV(64,", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateLong1(arg1, value1, r);
				l = VG_(sprintf)(s, ",");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateLong2(arg2, value2, r);
				l = VG_(sprintf)(s, "));\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
    }
  }
}

static
void instrumentWrTmpDivisionBinop(IRStmt* clone, IRExpr* arg1, IRExpr* arg2, Addr64 value1, IRExpr* value2)
{
  UShort r = isPropagation2(arg1, arg2);
  UInt ltmp = clone->Ist.WrTmp.tmp;
  UInt oprt = clone->Ist.WrTmp.data->Iex.Binop.op;
  if (r)
  {
    Char s[256];
    Int l = 0;
    taintTemp(ltmp);
#ifdef TAINTED_TRACE_PRINTOUT
    ppIRStmt(clone);
    VG_(printf) ("\n");
#endif
#ifdef TAINTED_BLOCKS_PRINTOUT
    if(newSB)
    {
      ppIRSB(printSB);
      VG_(printf) ("\n");
      newSB = False;
    }
#endif
    switch (oprt)
    {
#if defined(CUT_ASSERT_WITH_QUERY)
      case Iop_DivModU64to32:	if ((arg2->tag == Iex_RdTmp) && secondTainted(r) && (!filterDangerous || useFiltering()))
#else
      case Iop_DivModU64to32:	if ((arg2->tag == Iex_RdTmp) && secondTainted(r))
#endif
				{
				  l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=", curblock, arg2->Iex.RdTmp.tmp, curvisited);
				  my_write(fddanger, s, l);
				  printSizedFalse(arg2->Iex.RdTmp.tmp, fddanger);
#if defined(CUT_ASSERT_WITH_QUERY)
				  l = VG_(sprintf)(s, ");\nQUERY(FALSE);\n");
#else
				  if (!filterDangerous || useFiltering())
				  {
				    l = VG_(sprintf)(s, ");\nQUERY(FALSE);\n");
				  }
				  else
				  {
				    l = VG_(sprintf)(s, ");\n");
                                  }
#endif
				  my_write(fddanger, s, l);
				}
				l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=BVMOD(64,", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateLong1(arg1, value1, r);
				l = VG_(sprintf)(s, ",(0hex00000000 @ ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate2(arg2, value2, r);
				l = VG_(sprintf)(s, ")) | (BVDIV(64,");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateLong1(arg1, value1, r);
				l = VG_(sprintf)(s, ",(0hex00000000 @ ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate2(arg2, value2, r);
				l = VG_(sprintf)(s, ")) @ 0hex00000000)[63:0]);\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
#if defined(CUT_ASSERT_WITH_QUERY)
      case Iop_DivModS64to32:	if ((arg2->tag == Iex_RdTmp) && secondTainted(r) && (!filterDangerous || useFiltering()))
#else
      case Iop_DivModS64to32:	if ((arg2->tag == Iex_RdTmp) && secondTainted(r))
#endif
				{
				  l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=", curblock, arg2->Iex.RdTmp.tmp, curvisited);
				  my_write(fddanger, s, l);
				  printSizedFalse(arg2->Iex.RdTmp.tmp, fddanger);
#if defined(CUT_ASSERT_WITH_QUERY)
				  l = VG_(sprintf)(s, ");\nQUERY(FALSE);\n");
#else
				  if (!filterDangerous || useFiltering())
				  {
				    l = VG_(sprintf)(s, ");\nQUERY(FALSE);\n");
				  }
				  else
				  {
				    l = VG_(sprintf)(s, ");\n");
                                  }
#endif
				  my_write(fddanger, s, l);
				}
				l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=SBVMOD(64,", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateLong1(arg1, value1, r);
				l = VG_(sprintf)(s, ",(0hex00000000 @ ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate2(arg2, value2, r);
				l = VG_(sprintf)(s, ")) | (SBVDIV(64,");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateLong1(arg1, value1, r);
				l = VG_(sprintf)(s, ",(0hex00000000 @ ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate2(arg2, value2, r);
				l = VG_(sprintf)(s, ")) @ 0hex00000000)[63:0]);\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      default: 			break;
    }
  }
}

static
void instrumentWrTmpBinop(IRStmt* clone, IRExpr* arg1, IRExpr* arg2, IRExpr* value1, IRExpr* value2)
{
  UShort r = isPropagation2(arg1, arg2);
  UInt ltmp = clone->Ist.WrTmp.tmp;
  UInt oprt = clone->Ist.WrTmp.data->Iex.Binop.op;
  if (r)
  {
    Char s[256];
    Int l = 0;
    HWord sarg;
    UShort size;
    taintTemp(ltmp);
#ifdef TAINTED_TRACE_PRINTOUT
    ppIRStmt(clone);
    VG_(printf) ("\n");
#endif
#ifdef TAINTED_BLOCKS_PRINTOUT
    if(newSB)
    {
      ppIRSB(printSB);
      VG_(printf) ("\n");
      newSB = False;
    }
#endif
    switch (oprt)
    {
      case Iop_CmpEQ8:
      case Iop_CmpEQ16:
      case Iop_CmpEQ32:		l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=IF ", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    			 	translate1(arg1, value1, r);
    				l = VG_(sprintf)(s, "=");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    				translate2(arg2, value2, r);
    				l = VG_(sprintf)(s, " THEN ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
                                printSizedTrue(ltmp, fdtrace);
      				printSizedTrue(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ELSE ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
                                printSizedFalse(ltmp, fdtrace);
      				printSizedFalse(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ENDIF);\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_CmpLT32S:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=IF SBVLT(", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    			 	translate1(arg1, value1, r);
    				l = VG_(sprintf)(s, ", ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    				translate2(arg2, value2, r);
    				l = VG_(sprintf)(s, ") THEN ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
                                printSizedTrue(ltmp, fdtrace);
      				printSizedTrue(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ELSE ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
                                printSizedFalse(ltmp, fdtrace);
      				printSizedFalse(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ENDIF);\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_CmpLT32U:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=IF BVLT(", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    			 	translate1(arg1, value1, r);
    				l = VG_(sprintf)(s, ", ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    				translate2(arg2, value2, r);
    				l = VG_(sprintf)(s, ") THEN ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
                                printSizedTrue(ltmp, fdtrace);
      				printSizedTrue(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ELSE ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
                                printSizedFalse(ltmp, fdtrace);
      				printSizedFalse(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ENDIF);\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_CmpLE32S:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=IF SBVLE(", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    			 	translate1(arg1, value1, r);
    				l = VG_(sprintf)(s, ", ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    				translate2(arg2, value2, r);
    				l = VG_(sprintf)(s, ") THEN ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
                                printSizedTrue(ltmp, fdtrace);
      				printSizedTrue(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ELSE ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
                                printSizedFalse(ltmp, fdtrace);
      				printSizedFalse(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ENDIF);\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_CmpLE32U:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=IF BVLE(", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    			 	translate1(arg1, value1, r);
    				l = VG_(sprintf)(s, ", ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    				translate2(arg2, value2, r);
    				l = VG_(sprintf)(s, ") THEN ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
                                printSizedTrue(ltmp, fdtrace);
      				printSizedTrue(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ELSE ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
                                printSizedFalse(ltmp, fdtrace);
      				printSizedFalse(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ENDIF);\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;

      case Iop_CmpNE8:
      case Iop_CmpNE16:
      case Iop_CmpNE32:		l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=IF NOT(", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    			 	translate1(arg1, value1, r);
    				l = VG_(sprintf)(s, "=");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
    				translate2(arg2, value2, r);
    				l = VG_(sprintf)(s, ") THEN ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
                                printSizedTrue(ltmp, fdtrace);
      				printSizedTrue(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ELSE ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
                                printSizedFalse(ltmp, fdtrace);
      				printSizedFalse(ltmp, fddanger);
                                l = VG_(sprintf)(s, " ENDIF);\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_Add8:
      case Iop_Add16:
      case Iop_Add32:		if (oprt == Iop_Add8) size = 8;
				else if (oprt == Iop_Add16) size = 16;
				else size = 32;
				l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=BVPLUS(%u,", curblock, ltmp, curvisited, size);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate1(arg1, value1, r);
				l = VG_(sprintf)(s, ",");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate2(arg2, value2, r);
				l = VG_(sprintf)(s, "));\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_Sub8:
      case Iop_Sub16:
      case Iop_Sub32:		if (oprt == Iop_Sub8) size = 8;
				else if (oprt == Iop_Sub16) size = 16;
				else size = 32;
				l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=BVSUB(%u,", curblock, ltmp, curvisited, size);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate1(arg1, value1, r);
				l = VG_(sprintf)(s, ",");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate2(arg2, value2, r);
				l = VG_(sprintf)(s, "));\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_Mul8:
      case Iop_Mul16:
      case Iop_Mul32:		if (oprt == Iop_Mul8) size = 8;
				else if (oprt == Iop_Mul16) size = 16;
				else size = 32;
				l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=BVMULT(%u,", curblock, ltmp, curvisited, size);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate1(arg1, value1, r);
				l = VG_(sprintf)(s, ",");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate2(arg2, value2, r);
				l = VG_(sprintf)(s, "));\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_Or8:
      case Iop_Or16:
      case Iop_Or32:		l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate1(arg1, value1, r);
				l = VG_(sprintf)(s, "|");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate2(arg2, value2, r);
				l = VG_(sprintf)(s, ");\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_And8:
      case Iop_And16:
      case Iop_And32:		l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate1(arg1, value1, r);
				l = VG_(sprintf)(s, "&");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate2(arg2, value2, r);
				l = VG_(sprintf)(s, ");\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_Xor8:
      case Iop_Xor16:
      case Iop_Xor32:		l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=BVXOR(", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate1(arg1, value1, r);
				l = VG_(sprintf)(s, ",");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate2(arg2, value2, r);
				l = VG_(sprintf)(s, "));\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;

      case Iop_Sar8:
      case Iop_Sar16:
      case Iop_Sar32:		if (secondTainted(r))
				{
				  //break;
				}
				if (oprt == Iop_Sar8) size = 8;
				else if (oprt == Iop_Sar16) size = 16;
				else if (oprt == Iop_Sar32) size = 32;
				else size = 64;
				l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=SBVDIV(%u,", curblock, ltmp, curvisited, size);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate1(arg1, value1, r);
				l = VG_(sprintf)(s, ",");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translateToPowerOfTwo(arg2, value2, size);
				l = VG_(sprintf)(s, "));\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_Shl8:
      case Iop_Shl16:
      case Iop_Shl32:		if (secondTainted(r))
				{
				  //break;
				}
				if (oprt == Iop_Shl8) size = 8;
				else if (oprt == Iop_Shl16) size = 16;
				else size = 32;
				sarg = getDecimalValue(arg2, (HWord) value2);
				if (sarg == 0)
                                {
                                  l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=", curblock, ltmp, curvisited);
				  my_write(fdtrace, s, l);
				  my_write(fddanger, s, l);
                                  translate1(arg1, value1, r);
                                  l = VG_(sprintf)(s, ");\n");
				  my_write(fdtrace, s, l);
				  my_write(fddanger, s, l);
                                }
                                else
                                {
				  l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=(", curblock, ltmp, curvisited);
				  my_write(fdtrace, s, l);
				  my_write(fddanger, s, l);
				  translate1(arg1, value1, r);
				  l = VG_(sprintf)(s, " << %lu)", sarg);
				  my_write(fdtrace, s, l);
				  my_write(fddanger, s, l);
				  l = VG_(sprintf)(s, "[%u:0]);\n", size - 1);
				  my_write(fdtrace, s, l);
				  my_write(fddanger, s, l);
				}
				break;
      case Iop_Shr8:
      case Iop_Shr16:
      case Iop_Shr32:		if (secondTainted(r))
				{
				  //break;
				}
				sarg = getDecimalValue(arg2, (HWord) value2);
				if (sarg == 0)
                                {
                                  l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=", curblock, ltmp, curvisited);
				  my_write(fdtrace, s, l);
				  my_write(fddanger, s, l);
                                  translate1(arg1, value1, r);
                                  l = VG_(sprintf)(s, ");\n");
				  my_write(fdtrace, s, l);
				  my_write(fddanger, s, l);
                                }
                                else
                                {
				  l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=(", curblock, ltmp, curvisited);
				  my_write(fdtrace, s, l);
				  my_write(fddanger, s, l);
				  translate1(arg1, value1, r);
				  l = VG_(sprintf)(s, ">> %lu));\n", sarg);
				  my_write(fdtrace, s, l);
				  my_write(fddanger, s, l);
				}
				break;
#if defined(CUT_ASSERT_WITH_QUERY)
      case Iop_DivU32:		if ((arg2->tag == Iex_RdTmp) && secondTainted(r) && (!filterDangerous || useFiltering()))
#else
      case Iop_DivU32:		if ((arg2->tag == Iex_RdTmp) && secondTainted(r))
#endif
				{
				  l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=", curblock, arg2->Iex.RdTmp.tmp, curvisited);
				  my_write(fddanger, s, l);
				  printSizedFalse(arg2->Iex.RdTmp.tmp, fddanger);
#if defined(CUT_ASSERT_WITH_QUERY)
				  l = VG_(sprintf)(s, ");\nQUERY(FALSE);\n");
#else
				  if (!filterDangerous || useFiltering())
				  {
				    l = VG_(sprintf)(s, ");\nQUERY(FALSE);\n");
				  }
				  else
				  {
				    l = VG_(sprintf)(s, ");\n");
                                  }
#endif
				  my_write(fddanger, s, l);
				}
				l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=BVDIV(32,", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate1(arg1, value1, r);
				l = VG_(sprintf)(s, ",");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate2(arg2, value2, r);
				l = VG_(sprintf)(s, "));\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
#if defined(CUT_ASSERT_WITH_QUERY)
      case Iop_DivS32:		if ((arg2->tag == Iex_RdTmp) && secondTainted(r) && (!filterDangerous || useFiltering()))
#else
      case Iop_DivS32:		if ((arg2->tag == Iex_RdTmp) && secondTainted(r))
#endif
				{
				  l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=", curblock, arg2->Iex.RdTmp.tmp, curvisited);
				  my_write(fddanger, s, l);
				  printSizedFalse(arg2->Iex.RdTmp.tmp, fddanger);
#if defined(CUT_ASSERT_WITH_QUERY)
				  l = VG_(sprintf)(s, ");\nQUERY(FALSE);\n");
#else
				  if (!filterDangerous || useFiltering())
				  {
				    l = VG_(sprintf)(s, ");\nQUERY(FALSE);\n");
				  }
				  else
				  {
				    l = VG_(sprintf)(s, ");\n");
                                  }
#endif
      				  my_write(fddanger, s, l);
				}
				l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=SBVDIV(32,", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate1(arg1, value1, r);
				l = VG_(sprintf)(s, ",");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate2(arg2, value2, r);
				l = VG_(sprintf)(s, "));\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_8HLto16:		l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=((", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate1(arg1, value1, r);
				l = VG_(sprintf)(s, " @ 0hex00) | (0hex00 @ ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate2(arg2, value2, r);
				l = VG_(sprintf)(s, ")));\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_16HLto32:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=((", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate1(arg1, value1, r);
				l = VG_(sprintf)(s, " @ 0hex0000) | (0hex0000 @ ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate2(arg2, value2, r);
				l = VG_(sprintf)(s, ")));\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      case Iop_32HLto64:	l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=((", curblock, ltmp, curvisited);
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate1(arg1, value1, r);
				l = VG_(sprintf)(s, " @ 0hex00000000) | (0hex00000000 @ ");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				translate2(arg2, value2, r);
				l = VG_(sprintf)(s, ")));\n");
				my_write(fdtrace, s, l);
				my_write(fddanger, s, l);
				break;
      default: 			break;
    }
  }
}

//unlikely to be ever used
static
void instrumentStoreGet(IRStmt* clone, IRExpr* storeAddr, UInt offset)
{
  UShort size;
  HWord addr = (HWord) storeAddr;
  switch (clone->Ist.Store.data->Iex.Get.ty)
  {
    case Ity_I8:	size = 8;
			break;
    case Ity_I16:	size = 16;
			break;
    case Ity_I32:	size = 32;
			break;
    case Ity_I64:	size = 64;
			break;
    default:            return;
                        break;
  }
  if (size && VG_(HT_lookup)(taintedRegisters, offset) != NULL)
  {
    Char ss[256];
    Int l = 0, i;
    taintMemory(addr, size);
#ifdef TAINTED_TRACE_PRINTOUT
    ppIRStmt(clone);
    VG_(printf) ("\n");
#endif
#ifdef TAINTED_BLOCKS_PRINTOUT
    if(newSB)
    {
      ppIRSB(printSB);
      VG_(printf) ("\n");
      newSB = False;
    }
#endif

/* Changed switch to for. */
    for (i = 0; i < (size >> 3); i ++)
    {
#if defined(VGA_x86)
      l = VG_(sprintf)(ss, "memory_%d : ARRAY BITVECTOR(32) OF BITVECTOR(8) = memory_%d WITH [0hex%08x] := registers_%d[0hex%02x];\n", 
                       memory + 1 + i, memory + i, (UInt) (addr + i), registers, offset + i);
#elif defined(VGA_amd64)
      l = VG_(sprintf)(ss, "memory_%d : ARRAY BITVECTOR(64) OF BITVECTOR(8) = memory_%d WITH [0hex%016lx] := registers_%d[0hex%02x];\n", 
                       memory + 1 + i, memory + i, (HWord) (addr + i), registers, offset + i);
#endif
      my_write(fdtrace, ss, l);
      my_write(fddanger, ss, l);
    }
    memory += i;
  }
  else
  {
    untaintMemory(addr, size);
  }
}

static
void instrumentStoreRdTmp(IRStmt* clone, IRExpr* storeAddr, UInt tmp, UInt ltmp)
{
  UShort size = curNode->temps[tmp].size;
  HWord addr = (HWord) storeAddr;
#if defined(CUT_ASSERT_WITH_QUERY)
  if (VG_(HT_lookup)(taintedTemps, ltmp) != NULL && (!filterDangerous || useFiltering()))
#else
  if (VG_(HT_lookup)(taintedTemps, ltmp) != NULL)
#endif
  {
    Char s[256];
    Int l = 0;
    Addr addrs[256];
    Char format[256]; 
    const NSegment* seg;
    VG_(am_get_client_segment_starts)(addrs, 256);
    seg = VG_(am_find_nsegment)(addrs[0]);
#if defined(CUT_ASSERT_WITH_QUERY)
    VG_(sprintf)(format, "ASSERT(BVLT(t_%%llx_%%u_%%u, 0hex%%0%ux));\nQUERY(FALSE)\n",
                 curNode->temps[ltmp].size / 4);
#else
    if (!filterDangerous || useFiltering())
    {
      VG_(sprintf)(format, "ASSERT(BVLT(t_%%llx_%%u_%%u, 0hex%%0%ux));\nQUERY(FALSE)\n",
                 curNode->temps[ltmp].size / 4);
    }
    else
    {
      VG_(sprintf)(format, "ASSERT(BVLT(t_%%llx_%%u_%%u, 0hex%%0%ux));\n",
                 curNode->temps[ltmp].size / 4);
    }
#endif
    l = VG_(sprintf)(s, format, curblock, ltmp, curvisited, seg->start);
    my_write(fddanger, s, l);
  }
  if (VG_(HT_lookup)(taintedTemps, tmp) != NULL)
  {
    Char ss[256];
    Int l = 0, i;
    taintMemory(addr, size);
#ifdef TAINTED_TRACE_PRINTOUT
    ppIRStmt(clone);
    VG_(printf) ("\n");
#endif
#ifdef TAINTED_BLOCKS_PRINTOUT
    if(newSB)
    {
      ppIRSB(printSB);
      VG_(printf) ("\n");
      newSB = False;
    }
#endif
/* Changed switch to this */
    if (size == 8)
    {
#if defined(VGA_x86)
      l = VG_(sprintf)(ss, "memory_%d : ARRAY BITVECTOR(32) OF BITVECTOR(8) = memory_%d WITH [0hex%08x] := t_%llx_%u_%u;\n", 
                       memory + 1, memory, (UInt) addr, curblock, tmp, curvisited);
#elif defined(VGA_amd64)
      l = VG_(sprintf)(ss, "memory_%d : ARRAY BITVECTOR(64) OF BITVECTOR(8) = memory_%d WITH [0hex%016lx] := t_%llx_%u_%u;\n", 
                       memory + 1, memory, (HWord) addr, curblock, tmp, curvisited);
#endif
      my_write(fdtrace, ss, l);
      my_write(fddanger, ss, l);
      memory ++;
    }
    else
    {
      for (i = 0; i < (size >> 3); i ++)
      {
#if defined(VGA_x86)
        l = VG_(sprintf)(ss, "memory_%d : ARRAY BITVECTOR(32) OF BITVECTOR(8) = memory_%d WITH [0hex%08x] := t_%llx_%u_%u[%d:%d];\n", 
                         memory + 1 + i, memory + i, (UInt) (addr + i), curblock, tmp, curvisited, ((i + 1) << 3) - 1, i << 3);
#elif defined(VGA_amd64)
        l = VG_(sprintf)(ss, "memory_%d : ARRAY BITVECTOR(64) OF BITVECTOR(8) = memory_%d WITH [0hex%016lx] := t_%llx_%u_%u[%d:%d];\n", 
                       memory + 1 + i, memory + i, (HWord) (addr + i), curblock, tmp, curvisited, ((i + 1) << 3) - 1, i << 3);
#endif
        my_write(fdtrace, ss, l);
        my_write(fddanger, ss, l);
      }
      memory += i;
    }
  }
  else
  {
    untaintMemory(addr, size);
  }
}

static
void instrumentStoreConst(IRStmt* clone, IRExpr* addr)
{
  UShort size;
  switch (clone->Ist.Store.data->Iex.Const.con->tag)
  {
    case Ico_U8:	size = 8;
			break;
    case Ico_U16:	size = 16;
			break;
    case Ico_U32:	size = 32;
			break;
    case Ico_U64:	size = 64;
			break;
    default:            return;
                        break;
  }
  untaintMemory((HWord) addr, size);
}

static
void instrumentExitRdTmp(IRStmt* clone, IRExpr* guard, UInt tmp, ULong dst)
{
#if defined(CUT_ASSERT_WITH_QUERY)
  if (VG_(HT_lookup)(taintedTemps, tmp) != NULL && (!filterConditions || useFiltering()))
#else
  if (VG_(HT_lookup)(taintedTemps, tmp) != NULL)
#endif
  {
    Char s[256];
    Int l;
#ifdef TAINTED_TRACE_PRINTOUT
    ppIRStmt(clone);
    VG_(printf) ("\n");
#endif
#ifdef TAINTED_BLOCKS_PRINTOUT
    if(newSB)
    {
      ppIRSB(printSB);
      VG_(printf) ("\n");
      newSB = False;
    }
#endif
    l = VG_(sprintf)(s, "ASSERT(t_%llx_%u_%u=", curblock, tmp, curvisited);
    my_write(fdtrace, s, l);
    my_write(fddanger, s, l);
    if (dumpPrediction)
    {
      /* (Bool) ((HWord) ...) to get rid of pointer cast warning */
      actual[curdepth] = (Bool) ((HWord) guard); 
    }
    if ((HWord) guard == 1)
    {
      printSizedTrue(tmp, fdtrace);
      printSizedTrue(tmp, fddanger);
    }
    else
    {
      printSizedFalse(tmp, fdtrace);
      printSizedFalse(tmp, fddanger);
    }
    /* (Bool) ((HWord) ...) to get rid of pointer cast warning */
    if (checkPrediction && !divergence && (curdepth < depth) && ((Bool) ((HWord) guard) != prediction[curdepth]))
    {
      SysRes fd = VG_(open)("divergence.log", VKI_O_RDWR | VKI_O_TRUNC | VKI_O_CREAT, VKI_S_IRWXU | VKI_S_IRWXG | VKI_S_IRWXO);
      divergence = True;
      VG_(write)(fd.res, &divergence, sizeof(Bool));
      VG_(write)(fd.res, &curdepth, sizeof(Int));
      VG_(close)(fd.res);
    }
    l = VG_(sprintf)(s, ");\n");
    my_write(fdtrace, s, l);
    my_write(fddanger, s, l);
    if (checkPrediction && (curdepth == depth) && !divergence)
    {
      SysRes fd = VG_(open)("divergence.log", VKI_O_RDWR | VKI_O_TRUNC | VKI_O_CREAT, VKI_S_IRWXU | VKI_S_IRWXG | VKI_S_IRWXO);
      divergence = False;
      VG_(write)(fd.res, &divergence, sizeof(Bool));
      VG_(close)(fd.res);
    }
#if defined(CUT_ASSERT_WITH_QUERY)
    if (curdepth >= depth)
#else
    if (curdepth >= depth && (!filterConditions || useFiltering()))
#endif
    {
      l = VG_(sprintf)(s, "QUERY(FALSE);\n");
      my_write(fdtrace, s, l);
    }
    curdepth++;
    if (curdepth > depth + invertdepth)
    {
      dump(fdtrace);
      dump(fddanger);
      if (dumpCalls)
      {
        dump(fdfuncFilter);
      }
      if (dumpPrediction)
      {
        SysRes fd = VG_(open)("actual.log", VKI_O_RDWR | VKI_O_TRUNC | VKI_O_CREAT, VKI_S_IRWXU | VKI_S_IRWXG | VKI_S_IRWXO);
        VG_(write)(fd.res, actual, (depth + invertdepth) * sizeof(Bool));
        VG_(close)(fd.res);
      }
      if (replace)
      {
        Int fd = VG_(open)("replace_data", VKI_O_RDWR, VKI_S_IRWXU | VKI_S_IRWXG | VKI_S_IRWXO).res;
        Int i;
        VG_(write)(fd, &socketsNum, 4);
        for (i = 0; i < socketsNum; i++)
        {
          VG_(write)(fd, &(replace_data[i].length), sizeof(Int));
          VG_(write)(fd, replace_data[i].data, replace_data[i].length);
        }
        VG_(close)(fd);
      }
      VG_(exit)(0);
    }
  }
}

static
void instrumentPut(IRStmt* clone, IRSB* sbOut)
{
  IRDirty* di;
  UInt offset = clone->Ist.Put.offset;
  IRExpr* data = clone->Ist.Put.data;
  switch (data->tag)
  {
    case Iex_Load: 	di = unsafeIRDirty_0_N(0, "instrumentPutLoad", VG_(fnptr_to_fnentry)(&instrumentPutLoad), mkIRExprVec_3(mkIRExpr_HWord((HWord)  clone), mkIRExpr_HWord(offset), data->Iex.Load.addr));
                   	addStmtToIRSB(sbOut, IRStmt_Dirty(di));
                   	break;
    case Iex_Get:      	di = unsafeIRDirty_0_N(0, "instrumentPutGet", VG_(fnptr_to_fnentry)(&instrumentPutGet), mkIRExprVec_3(mkIRExpr_HWord((HWord) clone), mkIRExpr_HWord(offset), mkIRExpr_HWord(data->Iex.Get.offset)));
                   	addStmtToIRSB(sbOut, IRStmt_Dirty(di));
                   	break;
    case Iex_RdTmp:    	di = unsafeIRDirty_0_N(0, "instrumentPutRdTmp", VG_(fnptr_to_fnentry)(&instrumentPutRdTmp), mkIRExprVec_3(mkIRExpr_HWord((HWord) clone), mkIRExpr_HWord(offset), mkIRExpr_HWord(data->Iex.RdTmp.tmp)));
                   	addStmtToIRSB(sbOut, IRStmt_Dirty(di));
                   	break;
    case Iex_Const:	di = unsafeIRDirty_0_N(0, "instrumentPutConst", VG_(fnptr_to_fnentry)(&instrumentPutConst), mkIRExprVec_2(mkIRExpr_HWord((HWord) clone), mkIRExpr_HWord(offset)));
                   	addStmtToIRSB(sbOut, IRStmt_Dirty(di));
                   	break;
    default:		break;
  }
}

#if defined(VGA_x86)
static
IRExpr* adjustSize(IRSB* sbOut, IRTypeEnv* tyenv, IRExpr* arg)
{
  IRTemp tmp;
  IRExpr* e;
  IRType argty = typeOfIRExpr(tyenv, arg);
  switch (argty)
  {
    case Ity_I1:	tmp = newIRTemp(tyenv, Ity_I32);
			e = IRExpr_Unop(Iop_1Uto32, arg);
			addStmtToIRSB(sbOut, IRStmt_WrTmp(tmp, e));
			return IRExpr_RdTmp(tmp);
    case Ity_I8:	tmp = newIRTemp(tyenv, Ity_I32);
			e = IRExpr_Unop(Iop_8Uto32, arg);
			addStmtToIRSB(sbOut, IRStmt_WrTmp(tmp, e));
			return IRExpr_RdTmp(tmp);
    case Ity_I16:	tmp = newIRTemp(tyenv, Ity_I32);
			e = IRExpr_Unop(Iop_16Uto32, arg);
			addStmtToIRSB(sbOut, IRStmt_WrTmp(tmp, e));
			return IRExpr_RdTmp(tmp);
    case Ity_I32:	return arg;
    case Ity_I64:	if (arg->tag == Iex_Const)
			{
			  tmp = newIRTemp(tyenv, Ity_I64);
			  e = IRExpr_Const(arg->Iex.Const.con);
			  addStmtToIRSB(sbOut, IRStmt_WrTmp(tmp, e));
			  return IRExpr_RdTmp(tmp);
			}
			else
			{
			  return arg;
			}
    default:		return arg; break;
  }
}
#elif defined(VGA_amd64)
static
IRExpr* adjustSize(IRSB* sbOut, IRTypeEnv* tyenv, IRExpr* arg)
{
  IRTemp tmp;
  IRExpr* e;
  IRType argty = typeOfIRExpr(tyenv, arg);
  switch (argty)
  {
    case Ity_I1:	tmp = newIRTemp(tyenv, Ity_I64);
			e = IRExpr_Unop(Iop_1Uto64, arg);
			addStmtToIRSB(sbOut, IRStmt_WrTmp(tmp, e));
			return IRExpr_RdTmp(tmp);
    case Ity_I8:	tmp = newIRTemp(tyenv, Ity_I64);
			e = IRExpr_Unop(Iop_8Uto64, arg);
			addStmtToIRSB(sbOut, IRStmt_WrTmp(tmp, e));
			return IRExpr_RdTmp(tmp);
    case Ity_I16:	tmp = newIRTemp(tyenv, Ity_I64);
			e = IRExpr_Unop(Iop_16Uto64, arg);
			addStmtToIRSB(sbOut, IRStmt_WrTmp(tmp, e));
			return IRExpr_RdTmp(tmp);
    case Ity_I32:	tmp = newIRTemp(tyenv, Ity_I64);
			e = IRExpr_Unop(Iop_32Uto64, arg);
			addStmtToIRSB(sbOut, IRStmt_WrTmp(tmp, e));
			return IRExpr_RdTmp(tmp);
    case Ity_I64:	if (arg->tag == Iex_Const)
			{
			  tmp = newIRTemp(tyenv, Ity_I64);
			  e = IRExpr_Const(arg->Iex.Const.con);
			  addStmtToIRSB(sbOut, IRStmt_WrTmp(tmp, e));
			  return IRExpr_RdTmp(tmp);
			}
			else
			{
			  return arg;
			}
    case Ity_I128:	if (arg->tag == Iex_Const)
			{
			  tmp = newIRTemp(tyenv, Ity_I128);
			  e = IRExpr_Const(arg->Iex.Const.con);
			  addStmtToIRSB(sbOut, IRStmt_WrTmp(tmp, e));
			  return IRExpr_RdTmp(tmp);
			}
			else
			{
			  return arg;
			}
    default:		return arg; break;
  }
}
#endif

static
void instrumentWrTmp(IRStmt* clone, IRSB* sbOut, IRTypeEnv* tyenv)
{
  IRDirty* di;
  IRExpr* arg1,* arg2,* arg3,* arg4, * arg0;
  UInt tmp = clone->Ist.WrTmp.tmp;
  IRExpr* data = clone->Ist.WrTmp.data;
  IRExpr* value1,* value2, * value3;
  switch (data->tag)
  {
    case Iex_Load: 	if (data->Iex.Load.addr->tag == Iex_RdTmp)
			{
			  di = unsafeIRDirty_0_N(0, "instrumentWrTmpLoad", VG_(fnptr_to_fnentry)(&instrumentWrTmpLoad), 
                                                 mkIRExprVec_5(mkIRExpr_HWord((HWord) clone), mkIRExpr_HWord(tmp), data->Iex.Load.addr, 
                                                 mkIRExpr_HWord(data->Iex.Load.ty), mkIRExpr_HWord(data->Iex.Load.addr->Iex.RdTmp.tmp)));
                   	  addStmtToIRSB(sbOut, IRStmt_Dirty(di));
			}
                   	break;
    case Iex_Get:  	di = unsafeIRDirty_0_N(0, "instrumentWrTmpGet", VG_(fnptr_to_fnentry)(&instrumentWrTmpGet), mkIRExprVec_3(mkIRExpr_HWord((HWord) clone), mkIRExpr_HWord(tmp), mkIRExpr_HWord(data->Iex.Get.offset)));
                   	addStmtToIRSB(sbOut, IRStmt_Dirty(di));
                   	break;
    case Iex_RdTmp:	di = unsafeIRDirty_0_N(0, "instrumentWrTmpRdTmp", VG_(fnptr_to_fnentry)(&instrumentWrTmpRdTmp), mkIRExprVec_3(mkIRExpr_HWord((HWord) clone), mkIRExpr_HWord(tmp), mkIRExpr_HWord(data->Iex.RdTmp.tmp)));
                   	addStmtToIRSB(sbOut, IRStmt_Dirty(di));
                   	break;
    case Iex_Unop:	if (data->Iex.Unop.arg->tag == Iex_RdTmp)
                        {
			  di = unsafeIRDirty_0_N(0, "instrumentWrTmpUnop", VG_(fnptr_to_fnentry)(&instrumentWrTmpUnop), mkIRExprVec_4(mkIRExpr_HWord((HWord) clone), mkIRExpr_HWord(tmp), mkIRExpr_HWord(data->Iex.Unop.arg->Iex.RdTmp.tmp), mkIRExpr_HWord(data->Iex.Unop.op)));
                   	  addStmtToIRSB(sbOut, IRStmt_Dirty(di));
 			}
 			break;
    case Iex_Binop:	arg1 = data->Iex.Binop.arg1;
			arg2 = data->Iex.Binop.arg2;
                        value1 = adjustSize(sbOut, tyenv, arg1);
                        value2 = adjustSize(sbOut, tyenv, arg2);
                        if ((data->Iex.Binop.op == Iop_CmpEQ64) ||
      			    (data->Iex.Binop.op == Iop_CmpLT64S) ||
      			    (data->Iex.Binop.op == Iop_CmpLT64U) ||
      			    (data->Iex.Binop.op == Iop_CmpLE64S) ||
      			    (data->Iex.Binop.op == Iop_CmpLE64U) ||
      			    (data->Iex.Binop.op == Iop_CmpNE64) ||
      			    (data->Iex.Binop.op == Iop_Add64) ||
      			    (data->Iex.Binop.op == Iop_Sub64) ||
      			    (data->Iex.Binop.op == Iop_Mul64) ||
      			    (data->Iex.Binop.op == Iop_Or64) ||
      			    (data->Iex.Binop.op == Iop_And64) ||
      			    (data->Iex.Binop.op == Iop_Xor64) ||
      			    (data->Iex.Binop.op == Iop_Sar64) ||
      			    (data->Iex.Binop.op == Iop_Shl64) ||
      			    (data->Iex.Binop.op == Iop_Shr64) ||
      			    (data->Iex.Binop.op == Iop_DivU64) ||
      			    (data->Iex.Binop.op == Iop_DivS64))
			{

/* This part is unclear to me: on x86 we have 32-bit pointers, so when 
   we cast them (arg1 and arg2) to Addr64, which is unsigned long long and
   thus 64-bit , we lose upper bytes always (at least that's what I think
   is the way it works). Not only we don't need extra split to lower and 
   upper bytes, but we lose part of our values if arguments are really 64-bit.
   Am I getting it wrong? I'll change it for now and see if it works.
   
   Edit: and it works so far. */

/* 
#if defined(VGA_x86)
                          UInt value1UpperBytes = (((Addr64) arg1) & 0xffffffff00000000ULL) >> 32;
                          UInt value1LowerBytes = ((Addr64) arg1) & 0x00000000ffffffffULL;
                          UInt value2UpperBytes = (((Addr64) arg2) & 0xffffffff00000000ULL) >> 32;
                          UInt value2LowerBytes = ((Addr64) arg2) & 0x00000000ffffffffULL;
                          di = unsafeIRDirty_0_N(0, "instrumentWrTmpLongBinop", VG_(fnptr_to_fnentry)(&instrumentWrTmpLongBinop), 
                                                 mkIRExprVec_9(mkIRExpr_HWord((HWord) clone), mkIRExpr_HWord(data->Iex.Binop.op), mkIRExpr_HWord(tmp), 
                                                               mkIRExpr_HWord((HWord) arg1), mkIRExpr_HWord((HWord) arg2), 
                                                               mkIRExpr_HWord(value1LowerBytes), mkIRExpr_HWord(value1UpperBytes),  
                                                               mkIRExpr_HWord(value2LowerBytes), mkIRExpr_HWord(value2UpperBytes)));
                   	  addStmtToIRSB(sbOut, IRStmt_Dirty(di));
#elif defined(VGA_amd64)
                          di = unsafeIRDirty_0_N(0, "instrumentWrTmpLongBinop", VG_(fnptr_to_fnentry)(&instrumentWrTmpLongBinop), mkIRExprVec_5(mkIRExpr_HWord((HWord) clone), mkIRExpr_HWord((HWord) arg1), mkIRExpr_HWord((HWord) arg2), value1, value2));
                   	  addStmtToIRSB(sbOut, IRStmt_Dirty(di));
#endif
*/
                          di = unsafeIRDirty_0_N(0, "instrumentWrTmpLongBinop", VG_(fnptr_to_fnentry)(&instrumentWrTmpLongBinop), 
                                                 mkIRExprVec_5(mkIRExpr_HWord((HWord) clone), mkIRExpr_HWord((HWord) arg1), 
                                                               mkIRExpr_HWord((HWord) arg2), value1, value2));
			}
			else if ((data->Iex.Binop.op == Iop_DivModU64to32) || (data->Iex.Binop.op == Iop_DivModS64to32))
			{
			  di = unsafeIRDirty_0_N(0, "instrumentWrTmpDivisionBinop", VG_(fnptr_to_fnentry)(&instrumentWrTmpDivisionBinop), mkIRExprVec_5(mkIRExpr_HWord((HWord) clone), mkIRExpr_HWord((HWord) arg1), mkIRExpr_HWord((HWord) arg2), value1, value2));
                     	  addStmtToIRSB(sbOut, IRStmt_Dirty(di));
			}
			else if ((data->Iex.Binop.op - Iop_INVALID <= 128) &&
                                 (typeOfIRExpr(tyenv, arg1) - Ity_INVALID <= 5) &&
                                 (typeOfIRExpr(tyenv, arg2) - Ity_INVALID <= 5))
                        //do not try to instrument floating point operations
			{
                          di = unsafeIRDirty_0_N(0, "instrumentWrTmpBinop", VG_(fnptr_to_fnentry)(&instrumentWrTmpBinop), mkIRExprVec_5(mkIRExpr_HWord((HWord) clone), mkIRExpr_HWord((HWord) arg1), mkIRExpr_HWord((HWord) arg2), value1, value2));
                   	  addStmtToIRSB(sbOut, IRStmt_Dirty(di));
			}
			break;
    case Iex_Const:	break;
    case Iex_CCall:	if (!VG_(strcmp)(data->Iex.CCall.cee->name, "x86g_calculate_condition") ||
                            !VG_(strcmp)(data->Iex.CCall.cee->name, "amd64g_calculate_condition"))
			{
                          arg0 = data->Iex.CCall.args[0];
			  arg1 = data->Iex.CCall.args[1];
			  arg2 = data->Iex.CCall.args[2];
			  arg3 = data->Iex.CCall.args[3];
			  arg4 = data->Iex.CCall.args[4];
			  {
                            value2 = adjustSize(sbOut, tyenv, arg2);
                            value3 = adjustSize(sbOut, tyenv, arg3);
			    value1 = adjustSize(sbOut, tyenv, arg1);
			    di = unsafeIRDirty_0_N(0, "instrumentWrTmpCCall", VG_(fnptr_to_fnentry)(&instrumentWrTmpCCall), mkIRExprVec_6(mkIRExpr_HWord((HWord) clone), mkIRExpr_HWord((HWord) arg2), mkIRExpr_HWord((HWord) arg3), value1, value2, value3));
                   	    addStmtToIRSB(sbOut, IRStmt_Dirty(di));
			  }
			}
			break;
    default:            break;
  }
}

static
void instrumentStore(IRStmt* clone, IRSB* sbOut)
{
  IRDirty* di;
  IRExpr* addr = clone->Ist.Store.addr;
  IRExpr* data = clone->Ist.Store.data;
  switch (data->tag)
  {
    case Iex_Get:  	di = unsafeIRDirty_0_N(0, "instrumentStoreGet", VG_(fnptr_to_fnentry)(&instrumentStoreGet), mkIRExprVec_3(mkIRExpr_HWord((HWord) clone), addr, mkIRExpr_HWord(data->Iex.Get.offset)));
                   	addStmtToIRSB(sbOut, IRStmt_Dirty(di));
                   	break;
    case Iex_RdTmp:	if (addr->tag == Iex_RdTmp)
			{
			  di = unsafeIRDirty_0_N(0, "instrumentStoreRdTmp", VG_(fnptr_to_fnentry)(&instrumentStoreRdTmp), mkIRExprVec_4(mkIRExpr_HWord((HWord) clone), addr, mkIRExpr_HWord(data->Iex.RdTmp.tmp), mkIRExpr_HWord(addr->Iex.RdTmp.tmp)));
                   	  addStmtToIRSB(sbOut, IRStmt_Dirty(di));
			}
                   	break;
    case Iex_Const:	di = unsafeIRDirty_0_N(0, "instrumentStoreConst", VG_(fnptr_to_fnentry)(&instrumentStoreConst), mkIRExprVec_2(mkIRExpr_HWord((HWord) clone), addr));
                   	addStmtToIRSB(sbOut, IRStmt_Dirty(di));
                   	break;
    default:		break;
  }
}

static
void instrumentExit(IRStmt* clone, IRSB* sbOut, IRTypeEnv* tyenv)
{
  IRDirty* di;
  IRExpr* etemp;
  IRExpr* guard = clone->Ist.Exit.guard;
  ULong dst = clone->Ist.Exit.dst->Ico.U64;
  switch (guard->tag)
  {
    case Iex_RdTmp:	etemp = adjustSize(sbOut, tyenv, guard);
                	di = unsafeIRDirty_0_N(0, "instrumentExitRdTmp", VG_(fnptr_to_fnentry)(&instrumentExitRdTmp), mkIRExprVec_4(mkIRExpr_HWord((HWord) clone), etemp, mkIRExpr_HWord(guard->Iex.RdTmp.tmp), mkIRExpr_HWord(dst)));
                   	addStmtToIRSB(sbOut, IRStmt_Dirty(di));
                   	break;
    default:		break;
  }
}

static
void createTaintedTemp(UInt basicBlockLowerBytes, UInt basicBlockUpperBytes)
{
  Addr64 bbaddr = (((Addr64) basicBlockUpperBytes) << 32) ^ basicBlockLowerBytes;
  curNode = VG_(HT_lookup)(tempSizeTable, bbaddr);
  curNode->visited++;
  curvisited = curNode->visited - 1;
  curblock = bbaddr;
  if (taintedTemps != NULL)
  {
    VG_(HT_destruct)(taintedTemps);
  }
  taintedTemps = VG_(HT_construct)("taintedTemps");
}

static
IRSB* tg_instrument ( VgCallbackClosure* closure,
                      IRSB* sbIn,
                      VexGuestLayout* layout,
                      VexGuestExtents* vge,
                      IRType gWordTy, IRType hWordTy )
{
   IRTypeEnv* tyenv = sbIn->tyenv;
   Int i = 0;
   IRDirty*   di;
   IRSB*      sbOut;
   UInt iaddrUpperBytes, iaddrLowerBytes, basicBlockUpperBytes, basicBlockLowerBytes;

   if (gWordTy != hWordTy) {
      /* We don't currently support this case. */
      VG_(tool_panic)("host/guest word size mismatch");
   }
   
#ifdef TAINTED_BLOCKS_PRINTOUT
   newSB = True;
   printSB = sbIn;
#endif

   /* Set up SB */
   sbOut = deepCopyIRSBExceptStmts(sbIn);

   curblock = vge->base[0];

   curNode = VG_(malloc)("taintMemoryNode", sizeof(sizeNode));
   curNode->key = curblock;
   curNode->temps = VG_(malloc)("temps", tyenv->types_used * sizeof(size2Node));
   for (i = 0; i < tyenv->types_used; i++)
   {
     switch (tyenv->types[i])
     {
       case Ity_I1:	curNode->temps[i].size = 1;
		break;
       case Ity_I8:	curNode->temps[i].size = 8;
		break;
       case Ity_I16:	curNode->temps[i].size = 16;
		break;
       case Ity_I32:	curNode->temps[i].size = 32;
		break;
       case Ity_I64:	curNode->temps[i].size = 64;
		break;
       case Ity_I128:	curNode->temps[i].size = 128;
		break;
       case Ity_F32:	curNode->temps[i].size = 32;
		break;
       case Ity_F64:	curNode->temps[i].size = 64;
		break;
       case Ity_V128:	curNode->temps[i].size = 128;
		break;
       default: break;
     }
   }
   curNode->visited = 0;
   VG_(HT_add_node)(tempSizeTable, curNode);

   curvisited = 0;
   basicBlockUpperBytes = (UInt) (((ULong) (((ULong) ((HWord) vge->base[0])) & 0xffffffff00000000ULL)) >> 32); 
   basicBlockLowerBytes = (UInt) (vge->base[0] & 0x00000000ffffffffULL);

   i = 0;
   di = unsafeIRDirty_0_N(0, "createTaintedTemp", VG_(fnptr_to_fnentry)(&createTaintedTemp), mkIRExprVec_2(mkIRExpr_HWord(basicBlockLowerBytes), mkIRExpr_HWord(basicBlockUpperBytes)));
   addStmtToIRSB(sbOut, IRStmt_Dirty(di));
   for (;i < sbIn->stmts_used; i++)
   {
     IRStmt* clone = deepMallocIRStmt((IRStmt*) sbIn->stmts[i]);
     switch (sbIn->stmts[i]->tag)
     {
       case Ist_IMark:
         iaddrUpperBytes = (UInt) (((ULong) (sbIn->stmts[i]->Ist.IMark.addr & 0xffffffff00000000ULL)) >> 32);
         iaddrLowerBytes = (UInt) (sbIn->stmts[i]->Ist.IMark.addr & 0x00000000ffffffffULL);
         di = unsafeIRDirty_0_N(0, "instrumentIMark", VG_(fnptr_to_fnentry)(&instrumentIMark), mkIRExprVec_2(mkIRExpr_HWord(iaddrLowerBytes), mkIRExpr_HWord(iaddrUpperBytes)));
         addStmtToIRSB(sbOut, IRStmt_Dirty(di));
         break;
       case Ist_Put:
         instrumentPut(clone, sbOut);
         break;
       case Ist_WrTmp:
         instrumentWrTmp(clone, sbOut, sbOut->tyenv);
         break;
       case Ist_Store:
         instrumentStore(clone, sbOut);
         break;
       case Ist_Exit:
         instrumentExit(clone, sbOut, sbOut->tyenv);
         break;
       default: break;
     }
     addStmtToIRSB(sbOut, sbIn->stmts[i]);
   }
   return sbOut;
}

static void tg_fini(Int exitcode)
{
  dump(fdtrace);
  dump(fddanger);
  if (dumpCalls)
  {
    dump(fdfuncFilter);
  }
  if (dumpPrediction)
  {
    SysRes fd = VG_(open)("actual.log", VKI_O_RDWR | VKI_O_TRUNC | VKI_O_CREAT, VKI_S_IRWXU | VKI_S_IRWXG | VKI_S_IRWXO);
    VG_(write)(fd.res, actual, (depth + invertdepth) * sizeof(Bool));
    VG_(close)(fd.res);
  }
  if (checkPrediction && !divergence)
  {
    SysRes fd = VG_(open)("divergence.log", VKI_O_RDWR | VKI_O_TRUNC | VKI_O_CREAT, VKI_S_IRWXU | VKI_S_IRWXG | VKI_S_IRWXO);
    divergence = False;
    VG_(write)(fd.res, &divergence, sizeof(Bool));
    VG_(close)(fd.res);
  }
  if (replace)
  {
    Int fd = VG_(open)("replace_data", VKI_O_RDWR, VKI_S_IRWXU | VKI_S_IRWXG | VKI_S_IRWXO).res;
    Int i;
    VG_(write)(fd, &socketsNum, 4);
    for (i = 0; i < socketsNum; i++)
    {
      VG_(write)(fd, &(replace_data[i].length), sizeof(Int));
      VG_(write)(fd, replace_data[i].data, replace_data[i].length);
    }
    VG_(close)(fd);
  }
}

static Bool tg_process_cmd_line_option(Char* arg)
{
  /* Probably 1 Char* is enough, but this is easier to understand. */
  Char* inputfile;
  Char* addr;
  Char* filtertype;
  Char* funcname;
  Char* funcfilterfile;
  Char* inputfilterfile;
  if (VG_INT_CLO(arg, "--startdepth", depth))
  {
    depth -= 1;
    return True;
  }
  else if (VG_INT_CLO(arg, "--invertdepth", invertdepth))
  {
    return True;
  }
  else if (VG_STR_CLO(arg, "--port", addr))
  {
    port = (UShort) VG_(strtoll10)(addr, NULL);
    return True;
  }
  else if (VG_STR_CLO(arg, "--func-name", funcname))
  {
    parseFnName(funcname);
    return True;
  }
  else if (VG_STR_CLO(arg, "--func-filter-file", funcfilterfile))
  {
    Int fd = VG_(open)(funcfilterfile, VKI_O_RDWR, 0).res;
    parseFuncFilterFile(fd);
    VG_(close)(fd);
    return True;
  }
  else if (VG_STR_CLO(arg, "--input-filter-file", inputfilterfile))
  {
    parseInputFilterFile(inputfilterfile);
    inputFilterEnabled = True;
    return True;
  }
  else if (VG_STR_CLO(arg, "--host", addr))
  {
    Char* dot = VG_(strchr)(addr, '.');
    *dot = '\0';
    ip1 = (UShort) VG_(strtoll10)(addr, NULL);
    addr = dot + 1;
    dot = VG_(strchr)(addr, '.');
    *dot = '\0';
    ip2 = (UShort) VG_(strtoll10)(addr, NULL);
    addr = dot + 1;
    dot = VG_(strchr)(addr, '.');
    *dot = '\0';
    ip3 = (UShort) VG_(strtoll10)(addr, NULL);
    addr = dot + 1;
    ip4 = (UShort) VG_(strtoll10)(addr, NULL);
    return True;
  }
  else if (VG_STR_CLO(arg, "--file", inputfile))
  {
    stringNode* node;
    if (inputfiles == NULL)
    {
      inputfiles = VG_(HT_construct)("inputfiles");
    }
    node = VG_(malloc)("stringNode", sizeof(stringNode));
    node->key = hashCode(inputfile);
    node->filename = inputfile;
    node->declared = False;
    VG_(HT_add_node)(inputfiles, node);
    return True;
  }
  else if (VG_STR_CLO(arg, "--func-filter", filtertype))
  {
    if (!VG_(strcmp) (filtertype, "all"))
    {
      filterConditions = True;
      filterDangerous = True;
    }
    else if (!VG_(strcmp) (filtertype, "conds"))
    {
      filterConditions = True;
    }
    else if (!VG_(strcmp) (filtertype, "d_ops"))
    {
      filterDangerous = True;
    }
    else
    {
      return False;
    }
    return True;
  }
  else if (VG_BOOL_CLO(arg, "--dump-calls", dumpCalls))
  {
    dumpCalls = True;
    fdfuncFilter = VG_(open) ("calldump.log", VKI_O_RDWR, VKI_S_IRWXU | VKI_S_IRWXG | VKI_S_IRWXO).res;
    parseFuncFilterFile(fdfuncFilter);
    return True;
  }
  else if (VG_BOOL_CLO(arg, "--suppress-subcalls", suppressSubcalls))
  {
    suppressSubcalls = True;
    return True;
  }
  else if (VG_BOOL_CLO(arg, "--sockets",  sockets))
  {
    return True;
  }
  else if (VG_BOOL_CLO(arg, "--datagrams",  datagrams))
  {
    return True;
  }
  else if (VG_BOOL_CLO(arg, "--replace",  replace))
  {
    Int fd = VG_(open)("replace_data", VKI_O_RDWR, VKI_S_IRWXU | VKI_S_IRWXG | VKI_S_IRWXO).res;
    VG_(read)(fd, &socketsNum, 4);
    socketsBoundary = socketsNum;
    if (socketsNum > 0)
    {
      Int i;
      replace_data = (replaceData*) VG_(malloc)("replace_data", socketsNum * sizeof(replaceData));
      for (i = 0; i < socketsNum; i++)
      {
        VG_(read)(fd, &(replace_data[i].length), sizeof(Int));
        replace_data[i].data = (Char*) VG_(malloc)("replace_data", replace_data[i].length);
        VG_(read)(fd, replace_data[i].data, replace_data[i].length);
      }
    }
    else
    {
      replace_data = NULL;
    }
    VG_(close)(fd);
    return True;
  }
  else if VG_BOOL_CLO(arg, "--check-prediction",  checkPrediction)
  {
    if (depth > 0)
    {
      SysRes fd = VG_(open)("prediction.log", VKI_O_RDWR, VKI_S_IRWXU | VKI_S_IRWXG | VKI_S_IRWXO);
      checkPrediction = True;
      prediction = VG_(malloc)("prediction", depth * sizeof(Bool));
      VG_(read)(fd.res, prediction, depth * sizeof(Bool));
      VG_(close)(fd.res);
    }
    else
    {
      checkPrediction = False;
    }
    return True;
  }
  else if VG_BOOL_CLO(arg, "--dump-prediction",  dumpPrediction)
  {
    dumpPrediction = True;
    actual = VG_(malloc)("prediction", (depth + invertdepth) * sizeof(Bool));
    return True;
  }
  else
  {
    return False;
  }
}

static void tg_print_usage(void)
{
  VG_(printf)(
	"    --startdepth=<number>		the number of conditional jumps after\n"
	"					which the queries for the invertation of\n"
	"					consequent conditional jumps are emitted\n"
	"    --invertdepth=<number>		number of queries to be emitted\n"
	"    --filename=<name>			the name of the file with the input data\n"
	"    --dump-prediction=<yes, no>	indicates whether the file with conditional\n"
	"		 			jumps outcome prediction should be dumped\n"
	"    --check-prediction=<yes, no>	indicates whether the file with\n"
	" 					previously dumped prediction should\n"
	"					be used to check for the occurence\n"
	"					of divergence\n"
	"    --dump-calls=<yes, no>		enables dumping list of called functions\n"
	"    					to calldump.log\n"
	"    --func-filter=<conds, d_ops, all>	enables separate function analysis\n"
	"    					use conds to filter condition QUERY's\n"
	"    					use d_ops to filter dangerous operation QUERY's\n"
	"    					use all to filter all QUERY's\n"
	"    --func-name=<name>			the name of function to use for function separate analysis\n"
	"    --func-filter-file=<name>		the name of the file with function names\n"
	"    					for function separate analysis\n"
	"    --input-filter-file=<name>		the name of the file with input mask for input separate analysis\n"
        "  special options for sockets:\n"
        "    --sockets=<yes, no>                mark data read from TCP sockets as tainted\n"
        "    --datagrams=<yes, no>              mark data read from UDP sockets as tainted\n"
        "    --host=<IPv4 address>              IP address of the network connection (for TCP sockets only)\n"
        "    --port=<number>                    port number of the network connection (for TCP sockets only)\n"
        "    --replace=<name>                   name of the file with data for replacement\n"
  );
}

static void tg_print_debug_usage(void)
{
  VG_(printf)("");
}

static void tg_pre_clo_init(void)
{
  VG_(details_name)            ("Tracegrind");
  VG_(details_version)         ("1.0");
  VG_(details_description)     ("valgrind IR to STP declarations converter");
  VG_(details_copyright_author)("Copyright (C) iisaev");
  VG_(details_bug_reports_to)  ("iisaev@ispras.ru");
  VG_(basic_tool_funcs)        (tg_post_clo_init,
                                tg_instrument,
                                tg_fini);
  VG_(needs_syscall_wrapper)(pre_call,
			      post_call);
  VG_(track_post_mem_write)(tg_track_post_mem_write);
  VG_(track_new_mem_mmap)(tg_track_mem_mmap);

  VG_(needs_core_errors) ();
  VG_(needs_var_info) ();

  VG_(needs_command_line_options)(tg_process_cmd_line_option,
                                  tg_print_usage,
                                  tg_print_debug_usage);

  taintedMemory = VG_(HT_construct)("taintedMemory");
  taintedRegisters = VG_(HT_construct)("taintedRegisters");

  tempSizeTable = VG_(HT_construct)("tempSizeTable");
 
  funcNames = VG_(HT_construct)("funcNames");
  funcSignatures = VG_(HT_construct)("funcSignatures");
  inputFilter = VG_(HT_construct)("inputFilter");
  
  diFunctionName = VG_(malloc) ("diFunctionName", 256 * sizeof(Char));
      
  fdtrace = VG_(open)("trace.log", VKI_O_RDWR | VKI_O_TRUNC | VKI_O_CREAT, VKI_S_IRWXU | VKI_S_IRWXG | VKI_S_IRWXO).res;
  fddanger = VG_(open)("dangertrace.log", VKI_O_RDWR | VKI_O_TRUNC | VKI_O_CREAT, VKI_S_IRWXU | VKI_S_IRWXG | VKI_S_IRWXO).res;
#if defined(VGA_x86)
  my_write(fdtrace, "memory_0 : ARRAY BITVECTOR(32) OF BITVECTOR(8);\nregisters_0 : ARRAY BITVECTOR(8) OF BITVECTOR(8);\n", 98);
  my_write(fddanger, "memory_0 : ARRAY BITVECTOR(32) OF BITVECTOR(8);\nregisters_0 : ARRAY BITVECTOR(8) OF BITVECTOR(8);\n", 98);
#elif defined(VGA_amd64)
  my_write(fdtrace, "memory_0 : ARRAY BITVECTOR(64) OF BITVECTOR(8);\nregisters_0 : ARRAY BITVECTOR(8) OF BITVECTOR(8);\n", 98);
  my_write(fddanger, "memory_0 : ARRAY BITVECTOR(64) OF BITVECTOR(8);\nregisters_0 : ARRAY BITVECTOR(8) OF BITVECTOR(8);\n", 98);
#endif
  curdepth = 0;
}

VG_DETERMINE_INTERFACE_VERSION(tg_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
