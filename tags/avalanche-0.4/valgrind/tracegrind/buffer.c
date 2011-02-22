/*--------------------------------------------------------------------------------*/
/*-------------------------------- AVALANCHE -------------------------------------*/
/*--- Tracegring. Transforms IR tainted trace to STP declarations.    buffer.c ---*/
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

#include "buffer.h"
#include "pub_tool_mallocfree.h"

#define INIT_SIZE 1024
#define SIZE 16192

struct B
{
  Int fd;
  Char* buffer;
  UInt occ;
};

struct B bufs[5];

Int occ = 0;

void dump(Int fd)
{
  Int i = 0;
  for (; i < occ; i++)
  {
    if (bufs[i].fd == fd)
    {
      VG_(write)(fd, bufs[i].buffer, bufs[i].occ);
      VG_(close)(fd);
      return;
    }
  }
}

void my_write(Int fd, Char* buf, Int size)
{
  if (occ == 5)
  {
    return;
  }
  Int i = 0;
  for (; i < occ; i++)
  {
    if (bufs[i].fd == fd)
    {
      goto out;
    }
  }
  bufs[i].buffer = VG_(malloc)("buffer", SIZE);
  bufs[i].fd = fd;
  bufs[i].occ = 0;
  occ++;
out:
  if (bufs[i].occ + size >= SIZE)
  {
    VG_(write)(bufs[i].fd, bufs[i].buffer, bufs[i].occ);
    bufs[i].occ = 0;
  }
  Int j = 0;
  for (; j < size; j++)
  {
    bufs[i].buffer[bufs[i].occ + j] = buf[j];
  }
  bufs[i].occ += size;
}

