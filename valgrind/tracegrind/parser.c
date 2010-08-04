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
#include "pub_tool_vki.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_hashtable.h"

extern VgHashTable funcNames;
extern VgHashTable inputFilter;

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

void parseFnName (Char* fnName)
{
  Int l = VG_(strlen) (fnName), i = 0, j = 0;
  Bool nameStarted = False;
  Char* data;
  fnNode* node;
  if (!l) return;
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
  data = VG_(malloc) ("data", sizeof(Char) * j + 1);
  VG_(memcpy) (data, fnName, j + 1);
  node = VG_(malloc)("fnNode", sizeof(fnNode));
  node->key = hashCode(fnName);
  node->data = data;
  VG_(HT_add_node) (funcNames, node);
}

void parseFuncFilterFile (Int fd)
{
  Int fileLength = VG_(fsize) (fd);
  Char buf[256];
  Char c;
  Int nameOffset = 0;
  Bool isCommented = False;
  if (fileLength < 2)
  {
    return;
  }
  VG_(memset) (buf, 0, 256);
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
  Bool tmpNameUpdated = False;
  VG_(HT_ResetIter) (funcNames);
  Char tmpName[256];
  while ((curCheckName = (fnNode*) VG_(HT_Next) (funcNames)))
  {
    if (isCPPFunction(curCheckName->data))
    {  
      if (!tmpNameUpdated)
      {
        VG_(memcpy) (tmpName, fnName, VG_(strlen) (fnName));
        cutTemplates(tmpName);
        cutAffixes(tmpName);
        leaveFnName(tmpName);
        tmpNameUpdated = True;
      }
      if (cmpNames(fnName, curCheckName->data)) return True;
    }
    else if (cmpNames(tmpName, curCheckName->data)) return True;
  }
  return False;
}

Bool cmpNames (Char* fnName, Char* checkName)
{
  Int sizeFn = VG_(strlen) (fnName);
  Int sizeCh = VG_(strlen) (checkName);
  Int iFn = 0, iCh = 0;
  Char stopWildcardSymbol = False;
  Bool activeWildcard = False;
  if (sizeCh > sizeFn) return False;
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
  Int i, j = 0, a_bracketBalance = 0;
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
  Char* nameStart;
  Int i, initialI;
  if (paramStart == NULL) return False;
  *paramStart = '\0';
  nameStart = VG_(strrchr) (fnName, ':');
  initialI = (nameStart != NULL) ? (nameStart - fnName + 1) : 0;
  for (i = initialI; i < VG_(strlen) (fnName) + 1; i ++)
  {
    fnName[i - initialI] = fnName[i];
    if (fnName[i] == 0) break;
  }
  return True;
}

Bool parseInputFilterFile (Char* fileName)
{
  Char curNumber[20], curSymbol;
  Int curNumberLength = 0;
  UInt lastNumber = 0, i, newNumber;
  Bool isSequence = False;
  Bool isHex = False;
  Int fd = VG_(open) (fileName, VKI_O_RDONLY, VKI_S_IRWXU | VKI_S_IRWXG | VKI_S_IRWXO).res;
  while (VG_(read) (fd, &curSymbol, sizeof(Char)) > 0)
  {
    if (VG_(isdigit) (curSymbol) || curSymbol == 'x' || curSymbol == 'X' || 
        (curSymbol >= 'a' && curSymbol <= 'f') || (curSymbol >= 'A' && curSymbol <= 'F'))
    {
      if (!VG_(isdigit) (curSymbol)) isHex = True;
      curNumber[curNumberLength ++] = curSymbol;
      curNumber[curNumberLength] = '\0';
    }
    else if (curNumberLength != 0)
    {
      VgHashNode* node;
      newNumber = (UInt) ((isHex) ? VG_(strtoll16) (curNumber, NULL) : VG_(strtoll10) (curNumber, NULL));
      if (isSequence)
      {
        for (i = lastNumber + 1; i < newNumber; i ++)
        {
          node = VG_(malloc) ("inputfileNode", sizeof(VgHashNode));
          node->key = i;
         // VG_(printf) ("adding untainted offset %d\n", i);
        }
        isSequence = False;
      }
      else if (curSymbol == '-')
      {
        isSequence = True;
      }
      lastNumber = newNumber;
      node = VG_(malloc) ("inputfileNode", sizeof(VgHashNode));
      node->key = lastNumber;
      //VG_(printf) ("adding untainted offset %d\n", lastNumber);
      curNumberLength = 0;
    }
  }
  return True;
}
