/*--------------------------------------------------------------------------------*/
/*-------------------------------- AVALANCHE -------------------------------------*/
/*--- Tracegrind. Transforms IR tainted trace to STP declarations.    parser.c ---*/
/*--------------------------------------------------------------------------------*/

/*
   This file is part of Tracegrind, the Valgrind tool,
   which tracks tainted data coming from the specified file
   and converts IR trace to STP declarations.

   Copyright (C) 2010 Mikhail Ermakov
      mermakov@ispras.ru

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

#include "parser.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_hashtable.h"

extern VgHashTable funcNames;
extern VgHashTable funcSignatures;

Bool isStandardFunction (Char* objName)
{
  return ((VG_(strstr) (objName, "/libc-") != NULL) ||
          (VG_(strstr) (objName, "/ld-") != NULL) ||
          (VG_(strstr) (objName, "/libstdc++") != NULL) ||
          (VG_(strstr) (objName, "/libpthread-") != NULL));
}

Bool isCPPFunction (Char* fnName)
{
  return ((VG_(strchr) (fnName, '(') != NULL) ||
          (VG_(strchr) (fnName, '<') != NULL) ||
          (VG_(strchr) (fnName, ':') != NULL));
}

/*void parseFunction (Char* fnName, Bool isCPP)
{
  Int length = VG_(strlen) (fnName);
  if (length == 0) return;
  Bool isWildcard_st = (fnName[0] == '%');
  Bool isWildcard_end = (fnName[length - 1] == '%');
  if (!isWildcard_st && !isWildcard_end)
  {
     Char* data = VG_(malloc) ("data", sizeof(Char) * length);
     VG_(memcpy) (data, fnName, length);
     fnNode* node;
     node = VG_(malloc)("fnNode", sizeof(fnNode));
     node->key = hashCode(fnName);
     node->data = data;
     if (!isCPP) VG_(HT_add_node) (funcNames, node);
     else VG_(HT_add_node) (cppfuncNames, node);
  }
  else
  {
    Int startIndex = 0;
    if (isWildcard_st) startIndex ++;
    if (isWildcard_end) fnName[length - 1] = 0;
    Char* data = VG_(malloc) ("data", sizeof(Char) * (length - startIndex));
    VG_(memcpy) (data, fnName + startIndex, length - startIndex);
    fnWcardNode* node;
    node = VG_(malloc)("fnWcardNode", sizeof(fnNode));
    node->key = hashCode(fnName + startIndex);
    node->data = data;
    node->type = ((isWildcard_st) ? 1 : 0) + ((isWildcard_end) ? -1 : 0);
    VG_(HT_add_node) (fnWildcards, node);
  }
}*/
    

void parseFnName (Char* fnName)
{
  Int l = VG_(strlen) (fnName), i = 0, j = 0;
  if (!l) return;
  Bool isSignature = False;
  Bool nameStarted = False;
  if (fnName[0] == '$')
  {
    i = 1;
    isSignature = True;
  }
  while (i < l)
  {
    if (fnName[i] == ' ' && !nameStarted)
    {
      i ++;
      continue;
    }
    if (fnName[i] != ' ') nameStarted = True;
    fnName[j ++] = fnName[i ++];
  }
  if (j < i)
  {
    fnName[j] = '\0';
  }
  Char* data = VG_(malloc) ("data", sizeof(Char) * j + 1);
  VG_(memcpy) (data, fnName, j + 1);
  fnNode* node;
  node = VG_(malloc)("fnNode", sizeof(fnNode));
  node->key = hashCode(fnName);
  node->data = data;
  if (isSignature) VG_(HT_add_node) (funcSignatures, node);
  else VG_(HT_add_node) (funcNames, node);
}

void parseFuncFilterFile (Int fd)
{
  Int fileLength = VG_(fsize) (fd);
  if (fileLength < 2)
  {
    return;
  }
  Char buf[256];
  VG_(memset) (buf, 0, 256);
  Char c;
  Int nameOffset = 0;
  Bool isCommented = False;
  while ((VG_(read) (fd, &c, 1) > 0) && (fileLength -- > 0))
  {
    if (c == '\n')
    {
      if (!isCommented)
      {
        buf[nameOffset] = '\0';
        parseFnName(buf);
      }
      VG_(memset) (buf, 0, nameOffset);
      nameOffset = 0;
      isCommented = False;
    }
    else
    {
      if (nameOffset == 0 && c == '#') isCommented = True;
      else
      {
        buf[nameOffset ++] = c;
      }
    }
  }
}

Bool checkWildcards (Char* fnName)
{
  fnNode* curCheckName;
  VG_(HT_ResetIter) (funcSignatures);
  while (curCheckName = (fnNode*) VG_(HT_Next) (funcSignatures))
  {  
    if (cmpNames(fnName, curCheckName->data)) return True;
  }
  VG_(HT_ResetIter) (funcNames);
  cutTemplates(fnName);
  leaveFnName(fnName);
  while (curCheckName = (fnNode*) VG_(HT_Next) (funcNames))
  {  
    if (cmpNames(fnName, curCheckName->data))
    {
      return True;
    }
  }
  return False;
}

Bool cmpNames (Char* fnName, Char* checkName)
{
  Int sizeFn = VG_(strlen) (fnName);
  Int sizeCh = VG_(strlen) (checkName);
  if (sizeCh > sizeFn) return False;
  Int iFn = 0, iCh = 0;
  Char stopWildcardSymbol;
  Bool activeWildcard = False;
  for (iFn = 0; iFn < sizeFn; iFn ++)
  {
    if (checkName[iCh] == '?')
    {
      if (iCh + 1 == sizeCh) return True;
      stopWildcardSymbol = checkName[++ iCh];
      activeWildcard = True;
      iFn --;
    }
    else 
    {
      if (activeWildcard)
      {
        if (fnName[iFn] == stopWildcardSymbol) { iCh ++; activeWildcard = False; }
        else continue;
      }
      else
      {
        if (fnName[iFn] == checkName[iCh]) { iCh ++; if (iCh == sizeCh) { iFn ++; break; } }
        else iCh = 0;
      }
    }
  }
  if (iCh == sizeCh && iFn == sizeFn) return True;
  return False;
}

Bool cutTemplates(Char* fnName)
{
  Int a_bracketBalance = 0, i, j = 0, initialI = 0, length = VG_(strlen) (fnName);
  Char tmpName[256];
  if (((fnName[0] == '<') ? ++ a_bracketBalance : a_bracketBalance) || 
      ((fnName[0] == '>') ? -- a_bracketBalance : a_bracketBalance)) 
  {
    initialI ++;
  }
  for (i = initialI; i < length; i ++)
  {
    if (fnName[i] == '<') 
    {
      if (fnName[i - 1] == '<') { a_bracketBalance --; tmpName[j ++] = '<'; tmpName[j ++] = '<'; }
      else a_bracketBalance ++;
    }
    else if (fnName[i] == '>') 
    {
      if (fnName[i - 1] == '>') { a_bracketBalance ++; tmpName[j ++] = '<'; tmpName[j ++] = '<'; }
      else a_bracketBalance --;
    }  
    else if (!a_bracketBalance)
    {
      tmpName[j ++] = fnName[i];
    }
  }
  for (i = 0; i < length; i ++)
  {
    if (i < j) fnName[i] = tmpName[i];
    else
    {
      fnName[i] = 0;
      break;
    }
  }
  return True;
}

Bool cutAffixes (Char* fnName)
{
  Int length = VG_(strlen) (fnName);
#define CONST_SUFFIX_LENGTH 6
  if (length > CONST_SUFFIX_LENGTH)
  {
    if (VG_(strcmp) (fnName + length - CONST_SUFFIX_LENGTH, " const") == 0) 
    {
      *(fnName + length - CONST_SUFFIX_LENGTH) = '\0';
      length -=  CONST_SUFFIX_LENGTH;
    }
  }
#undef CONST_SUFFIX_LENGTH
  Int i, j = 0, a_bracketBalance = 0;
  for (i = 0; i < length; i ++)
  {
    if (fnName[i] == '(') break;
    switch (fnName[i])
    {
      case '<': a_bracketBalance ++; break;
      case '>': a_bracketBalance --; break;
      case ' ': if (!a_bracketBalance) j = i + 1;
                break;
      default : break;
    }
  }
  if (j != 0 && i == length) return False;
  if (j)
  {
    for (i = j; i < length; i ++)
    {
      fnName[i - j] = fnName[i];
    }
    fnName[i - j] = '\0';
  }
  return True;
}

Bool leaveFnName (Char* fnName)
{
  Char* paramStart = VG_(strchr) (fnName, '(');
  if (paramStart == NULL) return False;
  *paramStart = '\0';
  Char* nameStart = VG_(strrchr) (fnName, ':');
  Int i, initialI = (nameStart != NULL) ? (nameStart - fnName + 1) : 0;
  for (i = initialI; i < VG_(strlen) (fnName) + 1; i ++)
  {
    fnName[i - initialI] = fnName[i];
    if (fnName[i] == 0) break;
  }
  return True;
}

void printHTs ()
{
  VG_(HT_ResetIter) (funcNames);
  VG_(printf) ("fnNames:\n");
  fnNode* cur_n;
  while (cur_n = (fnNode*) VG_(HT_Next) (funcNames))
  {
    VG_(printf) ("%s\n", cur_n->data);
  }
}
