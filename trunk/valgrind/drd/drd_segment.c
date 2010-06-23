/*
  This file is part of drd, a thread error detector.

  Copyright (C) 2006-2009 Bart Van Assche <bart.vanassche@gmail.com>.

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


#include "drd_error.h"
#include "drd_segment.h"
#include "drd_thread.h"
#include "pub_tool_basics.h"      // Addr, SizeT
#include "pub_tool_errormgr.h"    // VG_(unique_error)()
#include "pub_tool_libcassert.h"  // tl_assert()
#include "pub_tool_libcbase.h"    // VG_(strlen)()
#include "pub_tool_libcprint.h"   // VG_(printf)()
#include "pub_tool_machine.h"     // VG_(get_SP)()
#include "pub_tool_mallocfree.h"  // VG_(malloc)(), VG_(free)()
#include "pub_tool_threadstate.h" // VG_INVALID_THREADID


/* Local variables. */

static ULong DRD_(s_segments_created_count);
static ULong DRD_(s_segments_alive_count);
static ULong DRD_(s_max_segments_alive_count);
static Bool DRD_(s_trace_segment) = False;


/* Function definitions. */

/**
 * Initialize the memory 'sg' points at.
 *  @note The creator and created thread ID's may be equal.
 */
static
void DRD_(sg_init)(Segment* const sg,
                   DrdThreadId const creator,
                   DrdThreadId const created)
{
  Segment* creator_sg;
  ThreadId vg_created = DRD_(DrdThreadIdToVgThreadId)(created);

  tl_assert(sg);
  tl_assert(creator == DRD_INVALID_THREADID
            || DRD_(IsValidDrdThreadId)(creator));

  creator_sg = (creator != DRD_INVALID_THREADID
                ? DRD_(thread_get_segment)(creator) : 0);

  sg->next = 0;
  sg->prev = 0;
  sg->refcnt = 1;

  if (vg_created != VG_INVALID_THREADID && VG_(get_SP)(vg_created) != 0)
    sg->stacktrace = VG_(record_ExeContext)(vg_created, 0);
  else
    sg->stacktrace = 0;

  if (creator_sg)
    DRD_(vc_copy)(&sg->vc, &creator_sg->vc);
  else
    DRD_(vc_init)(&sg->vc, 0, 0);
  DRD_(vc_increment)(&sg->vc, created);
  sg->bm = DRD_(bm_new)();

  if (DRD_(s_trace_segment))
  {
    char msg[256];
    VG_(snprintf)(msg, sizeof(msg),
                  "New segment for thread %d/%d with vc ",
                  created != VG_INVALID_THREADID
                  ? DRD_(DrdThreadIdToVgThreadId)(created)
                  : DRD_INVALID_THREADID,
                  created);
    DRD_(vc_snprint)(msg + VG_(strlen)(msg), sizeof(msg) - VG_(strlen)(msg),
               &sg->vc);
    VG_(message)(Vg_UserMsg, "%s", msg);
  }
}

/** Deallocate the memory that was allocated by sg_init(). */
static void DRD_(sg_cleanup)(Segment* const sg)
{
  tl_assert(sg);
  tl_assert(sg->refcnt == 0);

  DRD_(vc_cleanup)(&sg->vc);
  DRD_(bm_delete)(sg->bm);
  sg->bm = 0;
}

/** Allocate and initialize a new segment. */
Segment* DRD_(sg_new)(ThreadId const creator, ThreadId const created)
{
  Segment* sg;

  DRD_(s_segments_created_count)++;
  DRD_(s_segments_alive_count)++;
  if (DRD_(s_max_segments_alive_count) < DRD_(s_segments_alive_count))
    DRD_(s_max_segments_alive_count) = DRD_(s_segments_alive_count);

  sg = VG_(malloc)("drd.segment.sn.1", sizeof(*sg));
  tl_assert(sg);
  DRD_(sg_init)(sg, creator, created);
  return sg;
}

static void DRD_(sg_delete)(Segment* const sg)
{
#if 1
  if (DRD_(sg_get_trace)())
  {
    char msg[256];
    VG_(snprintf)(msg, sizeof(msg),
                  "Discarding the segment with vector clock ");
    DRD_(vc_snprint)(msg + VG_(strlen)(msg), sizeof(msg) - VG_(strlen)(msg),
               &sg->vc);
    VG_(message)(Vg_UserMsg, "%s", msg);
  }
#endif

  DRD_(s_segments_alive_count)--;

  tl_assert(sg);
  DRD_(sg_cleanup)(sg);
  VG_(free)(sg);
}

/** Query the reference count of the specified segment. */
int DRD_(sg_get_refcnt)(const Segment* const sg)
{
  tl_assert(sg);

  return sg->refcnt;
}

/** Increment the reference count of the specified segment. */
Segment* DRD_(sg_get)(Segment* const sg)
{
  tl_assert(sg);

  sg->refcnt++;
  return sg;
}

/**
 * Decrement the reference count of the specified segment and deallocate the
 * segment if the reference count became zero.
 */
void DRD_(sg_put)(Segment* const sg)
{
  if (sg == 0)
    return;

  if (DRD_(s_trace_segment))
  {
    char msg[256];
    VG_(snprintf)(msg, sizeof(msg),
                  "Decrementing segment reference count %d -> %d with vc ",
                  sg->refcnt, sg->refcnt - 1);
    DRD_(vc_snprint)(msg + VG_(strlen)(msg), sizeof(msg) - VG_(strlen)(msg),
               &sg->vc);
    VG_(message)(Vg_UserMsg, "%s", msg);
  }

  tl_assert(sg->refcnt >= 1);

  if (--sg->refcnt == 0)
  {
    DRD_(sg_delete)(sg);
  }
}

/** Merge sg1 and sg2 into sg1. */
void DRD_(sg_merge)(const Segment* const sg1, Segment* const sg2)
{
  tl_assert(sg1);
  tl_assert(sg1->refcnt == 1);
  tl_assert(sg2);
  tl_assert(sg2->refcnt == 1);

  if (DRD_(s_trace_segment))
  {
      char msg[256];

      VG_(snprintf)(msg, sizeof(msg), "Merging segments with vector clocks ");
      DRD_(vc_snprint)(msg + VG_(strlen)(msg), sizeof(msg) - VG_(strlen)(msg),
                 &sg1->vc);
      VG_(snprintf)(msg + VG_(strlen)(msg), sizeof(msg) - VG_(strlen)(msg),
                    " and ");
      DRD_(vc_snprint)(msg + VG_(strlen)(msg), sizeof(msg) - VG_(strlen)(msg),
                 &sg2->vc);
      VG_(message)(Vg_UserMsg, "%s", msg);
  }

  // Keep sg1->stacktrace.
  // Keep sg1->vc.
  // Merge sg2->bm into sg1->bm.
  DRD_(bm_merge2)(sg1->bm, sg2->bm);
}

/** Print the vector clock and the bitmap of the specified segment. */
void DRD_(sg_print)(const Segment* const sg)
{
  tl_assert(sg);
  VG_(printf)("vc: ");
  DRD_(vc_print)(&sg->vc);
  VG_(printf)("\n");
  DRD_(bm_print)(sg->bm);
}

/** Query whether segment tracing has been enabled. */
Bool DRD_(sg_get_trace)(void)
{
  return DRD_(s_trace_segment);
}

/** Enable or disable segment tracing. */
void DRD_(sg_set_trace)(Bool const trace_segment)
{
  tl_assert(trace_segment == False || trace_segment == True);
  DRD_(s_trace_segment) = trace_segment;
}

ULong DRD_(sg_get_segments_created_count)(void)
{
  return DRD_(s_segments_created_count);
}

ULong DRD_(sg_get_segments_alive_count)(void)
{
  return DRD_(s_segments_alive_count);
}

ULong DRD_(sg_get_max_segments_alive_count)(void)
{
  return DRD_(s_max_segments_alive_count);
}
