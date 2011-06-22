/*--------------------------------------------------------------------*/
/*--- Replacements for strcpy(), memcpy() et al, which run on the  ---*/
/*--- simulated CPU.                                               ---*/
/*---                                          tg_replace_strmem.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Tracegrind, the Valgrind tool,
   which tracks tainted data coming from the specified file
   and converts IR trace to STP declarations.
   
   Wrapper functions are duplicated from
   mc_replace_strmem.c - copyright (C) 2000-2010 Julian Seward 
                         jseward@acm.org

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
#include "pub_tool_redir.h"
#include "pub_tool_tooliface.h"
#include "valgrind.h"

#define STRRCHR(soname, fnname) \
   char* VG_REPLACE_FUNCTION_ZU(soname,fnname)( const char* s, int c ); \
   char* VG_REPLACE_FUNCTION_ZU(soname,fnname)( const char* s, int c ) \
   { \
      UChar  ch   = (UChar)((UInt)c); \
      UChar* p    = (UChar*)s; \
      UChar* last = NULL; \
      while (True) { \
         if (*p == ch) last = p; \
         if (*p == 0) return last; \
         p++; \
      } \
   }

// Apparently rindex() is the same thing as strrchr()
STRRCHR(VG_Z_LIBC_SONAME,   strrchr)
STRRCHR(VG_Z_LIBC_SONAME,   rindex)
#if defined(VGO_linux)
STRRCHR(VG_Z_LIBC_SONAME,   __GI_strrchr)
STRRCHR(VG_Z_LD_LINUX_SO_2, rindex)
#endif
   

#define STRCHR(soname, fnname) \
   char* VG_REPLACE_FUNCTION_ZU(soname,fnname) ( const char* s, int c ); \
   char* VG_REPLACE_FUNCTION_ZU(soname,fnname) ( const char* s, int c ) \
   { \
      UChar  ch = (UChar)((UInt)c); \
      UChar* p  = (UChar*)s; \
      while (True) { \
         if (*p == ch) return p; \
         if (*p == 0) return NULL; \
         p++; \
      } \
   }

// Apparently index() is the same thing as strchr()
STRCHR(VG_Z_LIBC_SONAME,          strchr)
STRCHR(VG_Z_LIBC_SONAME,          index)
#if defined(VGO_linux)
STRCHR(VG_Z_LIBC_SONAME,          __GI_strchr)
STRCHR(VG_Z_LD_LINUX_SO_2,        strchr)
STRCHR(VG_Z_LD_LINUX_SO_2,        index)
STRCHR(VG_Z_LD_LINUX_X86_64_SO_2, strchr)
STRCHR(VG_Z_LD_LINUX_X86_64_SO_2, index)
#endif


#define STRCAT(soname, fnname) \
   char* VG_REPLACE_FUNCTION_ZU(soname,fnname) ( char* dst, const char* src ); \
   char* VG_REPLACE_FUNCTION_ZU(soname,fnname) ( char* dst, const char* src ) \
   { \
      const Char* src_orig = src; \
            Char* dst_orig = dst; \
      while (*dst) dst++; \
      while (*src) *dst++ = *src++; \
      *dst = 0; \
      return dst_orig; \
   }

STRCAT(VG_Z_LIBC_SONAME, strcat)
#if defined(VGO_linux)
STRCAT(VG_Z_LIBC_SONAME, __GI_strcat)
#endif

#define STRNCAT(soname, fnname) \
   char* VG_REPLACE_FUNCTION_ZU(soname,fnname) \
            ( char* dst, const char* src, SizeT n ); \
   char* VG_REPLACE_FUNCTION_ZU(soname,fnname) \
            ( char* dst, const char* src, SizeT n ) \
   { \
      const Char* src_orig = src; \
            Char* dst_orig = dst; \
      SizeT m = 0; \
      \
      while (*dst) dst++; \
      while (m < n && *src) { m++; *dst++ = *src++; } /* concat <= n chars */ \
      *dst = 0;                                       /* always add null   */ \
      return dst_orig; \
   }

STRNCAT(VG_Z_LIBC_SONAME, strncat)
#if defined(VGO_darwin)
STRNCAT(VG_Z_DYLD,        strncat)
#endif

#define STRNLEN(soname, fnname) \
   SizeT VG_REPLACE_FUNCTION_ZU(soname,fnname) ( const char* str, SizeT n ); \
   SizeT VG_REPLACE_FUNCTION_ZU(soname,fnname) ( const char* str, SizeT n ) \
   { \
      SizeT i = 0; \
      while (i < n && str[i] != 0) i++; \
      return i; \
   }

STRNLEN(VG_Z_LIBC_SONAME, strnlen)
#if defined(VGO_linux)
STRNLEN(VG_Z_LIBC_SONAME, __GI_strnlen)
#endif
   

// Note that this replacement often doesn't get used because gcc inlines
// calls to strlen() with its own built-in version.  This can be very
// confusing if you aren't expecting it.  Other small functions in this file
// may also be inline by gcc.
#define STRLEN(soname, fnname) \
   SizeT VG_REPLACE_FUNCTION_ZU(soname,fnname)( const char* str ); \
   SizeT VG_REPLACE_FUNCTION_ZU(soname,fnname)( const char* str ) \
   { \
      SizeT i = 0; \
      while (str[i] != 0) i++; \
      return i; \
   }

STRLEN(VG_Z_LIBC_SONAME,          strlen)
#if defined(VGO_linux)
STRLEN(VG_Z_LIBC_SONAME,          __GI_strlen)
STRLEN(VG_Z_LD_LINUX_SO_2,        strlen)
STRLEN(VG_Z_LD_LINUX_X86_64_SO_2, strlen)
#endif


#define STRCPY(soname, fnname) \
   char* VG_REPLACE_FUNCTION_ZU(soname, fnname) ( char* dst, const char* src ); \
   char* VG_REPLACE_FUNCTION_ZU(soname, fnname) ( char* dst, const char* src ) \
   { \
      const Char* src_orig = src; \
            Char* dst_orig = dst; \
      \
      while (*src) *dst++ = *src++; \
      *dst = 0; \
      return dst_orig; \
   }

STRCPY(VG_Z_LIBC_SONAME, strcpy)
#if defined(VGO_linux)
STRCPY(VG_Z_LIBC_SONAME, __GI_strcpy)
#endif


#define STRNCPY(soname, fnname) \
   char* VG_REPLACE_FUNCTION_ZU(soname, fnname) \
            ( char* dst, const char* src, SizeT n ); \
   char* VG_REPLACE_FUNCTION_ZU(soname, fnname) \
            ( char* dst, const char* src, SizeT n ) \
   { \
      const Char* src_orig = src; \
            Char* dst_orig = dst; \
      SizeT m = 0; \
      \
      while (m   < n && *src) { m++; *dst++ = *src++; } \
      while (m++ < n) *dst++ = 0;         /* must pad remainder with nulls */ \
      return dst_orig; \
   }

STRNCPY(VG_Z_LIBC_SONAME, strncpy)
#if defined(VGO_linux)
STRNCPY(VG_Z_LIBC_SONAME, __GI_strncpy)
#endif


#define STRNCMP(soname, fnname) \
   int VG_REPLACE_FUNCTION_ZU(soname,fnname) \
          ( const char* s1, const char* s2, SizeT nmax ); \
   int VG_REPLACE_FUNCTION_ZU(soname,fnname) \
          ( const char* s1, const char* s2, SizeT nmax ) \
   { \
      SizeT n = 0; \
      while (True) { \
         if (n >= nmax) return 0; \
         if (*s1 == 0 && *s2 == 0) return 0; \
         if (*s1 == 0) return -1; \
         if (*s2 == 0) return 1; \
         \
         if (*(unsigned char*)s1 < *(unsigned char*)s2) return -1; \
         if (*(unsigned char*)s1 > *(unsigned char*)s2) return 1; \
         \
         s1++; s2++; n++; \
      } \
   }

STRNCMP(VG_Z_LIBC_SONAME, strncmp)
#if defined(VGO_linux)
STRNCMP(VG_Z_LIBC_SONAME, __GI_strncmp)
#endif


#define STRCMP(soname, fnname) \
   int VG_REPLACE_FUNCTION_ZU(soname,fnname) \
          ( const char* s1, const char* s2 ); \
   int VG_REPLACE_FUNCTION_ZU(soname,fnname) \
          ( const char* s1, const char* s2 ) \
   { \
      register unsigned char c1; \
      register unsigned char c2; \
      while (True) { \
         c1 = *(unsigned char *)s1; \
         c2 = *(unsigned char *)s2; \
         if (c1 != c2) break; \
         if (c1 == 0) break; \
         s1++; s2++; \
      } \
      if ((unsigned char)c1 < (unsigned char)c2) return -1; \
      if ((unsigned char)c1 > (unsigned char)c2) return 1; \
      return 0; \
   }

STRCMP(VG_Z_LIBC_SONAME,          strcmp)
#if defined(VGO_linux)
STRCMP(VG_Z_LIBC_SONAME,          __GI_strcmp)
STRCMP(VG_Z_LD_LINUX_X86_64_SO_2, strcmp)
STRCMP(VG_Z_LD64_SO_1,            strcmp)
#endif


#define MEMCHR(soname, fnname) \
   void* VG_REPLACE_FUNCTION_ZU(soname,fnname) (const void *s, int c, SizeT n); \
   void* VG_REPLACE_FUNCTION_ZU(soname,fnname) (const void *s, int c, SizeT n) \
   { \
      SizeT i; \
      UChar c0 = (UChar)c; \
      UChar* p = (UChar*)s; \
      for (i = 0; i < n; i++) \
         if (p[i] == c0) return (void*)(&p[i]); \
      return NULL; \
   }

MEMCHR(VG_Z_LIBC_SONAME, memchr)
#if defined(VGO_darwin)
MEMCHR(VG_Z_DYLD,        memchr)
#endif


#define MEMCPY(soname, fnname) \
   void* VG_REPLACE_FUNCTION_ZU(soname,fnname) \
            ( void *dst, const void *src, SizeT len ); \
   void* VG_REPLACE_FUNCTION_ZU(soname,fnname) \
            ( void *dst, const void *src, SizeT len ) \
   { \
      const Addr WS = sizeof(UWord); /* 8 or 4 */ \
      const Addr WM = WS - 1;        /* 7 or 3 */ \
      \
      if (dst < src) { \
      \
         /* Copying backwards. */ \
         SizeT n = len; \
         Addr  d = (Addr)dst; \
         Addr  s = (Addr)src; \
         \
         if (((s^d) & WM) == 0) { \
            /* s and d have same UWord alignment. */ \
            /* Pull up to a UWord boundary. */ \
            while ((s & WM) != 0 && n >= 1) \
               { *(UChar*)d = *(UChar*)s; s += 1; d += 1; n -= 1; } \
            /* Copy UWords. */ \
            while (n >= WS) \
               { *(UWord*)d = *(UWord*)s; s += WS; d += WS; n -= WS; } \
            if (n == 0) \
               return dst; \
         } \
         if (((s|d) & 1) == 0) { \
            /* Both are 16-aligned; copy what we can thusly. */ \
            while (n >= 2) \
               { *(UShort*)d = *(UShort*)s; s += 2; d += 2; n -= 2; } \
         } \
         /* Copy leftovers, or everything if misaligned. */ \
         while (n >= 1) \
            { *(UChar*)d = *(UChar*)s; s += 1; d += 1; n -= 1; } \
      \
      } else if (dst > src) { \
      \
         SizeT n = len; \
         Addr  d = ((Addr)dst) + n; \
         Addr  s = ((Addr)src) + n; \
         \
         /* Copying forwards. */ \
         if (((s^d) & WM) == 0) { \
            /* s and d have same UWord alignment. */ \
            /* Back down to a UWord boundary. */ \
            while ((s & WM) != 0 && n >= 1) \
               { s -= 1; d -= 1; *(UChar*)d = *(UChar*)s; n -= 1; } \
            /* Copy UWords. */ \
            while (n >= WS) \
               { s -= WS; d -= WS; *(UWord*)d = *(UWord*)s; n -= WS; } \
            if (n == 0) \
               return dst; \
         } \
         if (((s|d) & 1) == 0) { \
            /* Both are 16-aligned; copy what we can thusly. */ \
            while (n >= 2) \
               { s -= 2; d -= 2; *(UShort*)d = *(UShort*)s; n -= 2; } \
         } \
         /* Copy leftovers, or everything if misaligned. */ \
         while (n >= 1) \
            { s -= 1; d -= 1; *(UChar*)d = *(UChar*)s; n -= 1; } \
         \
      } \
      \
      return dst; \
   }

MEMCPY(VG_Z_LIBC_SONAME, memcpy)
#if defined(VGO_linux)
MEMCPY(VG_Z_LD_SO_1,     memcpy) /* ld.so.1 */
MEMCPY(VG_Z_LD64_SO_1,   memcpy) /* ld64.so.1 */
#elif defined(VGO_darwin)
MEMCPY(VG_Z_DYLD,        memcpy)
#endif
/* icc9 blats these around all over the place.  Not only in the main
   executable but various .so's.  They are highly tuned and read
   memory beyond the source boundary (although work correctly and
   never go across page boundaries), so give errors when run natively,
   at least for misaligned source arg.  Just intercepting in the exe
   only until we understand more about the problem.  See
   http://bugs.kde.org/show_bug.cgi?id=139776
 */
MEMCPY(NONE, _intel_fast_memcpy)


#define MEMCMP(soname, fnname) \
   int VG_REPLACE_FUNCTION_ZU(soname,fnname) \
          ( const void *s1V, const void *s2V, SizeT n ); \
   int VG_REPLACE_FUNCTION_ZU(soname,fnname) \
          ( const void *s1V, const void *s2V, SizeT n ) \
   { \
      int res; \
      unsigned char a0; \
      unsigned char b0; \
      unsigned char* s1 = (unsigned char*)s1V; \
      unsigned char* s2 = (unsigned char*)s2V; \
      \
      while (n != 0) { \
         a0 = s1[0]; \
         b0 = s2[0]; \
         s1 += 1; \
         s2 += 1; \
         res = ((int)a0) - ((int)b0); \
         if (res != 0) \
            return res; \
         n -= 1; \
      } \
      return 0; \
   }

MEMCMP(VG_Z_LIBC_SONAME, memcmp)
MEMCMP(VG_Z_LIBC_SONAME, bcmp)
#if defined(VGO_linux)
MEMCMP(VG_Z_LD_SO_1,     bcmp)
#endif


/* Copy SRC to DEST, returning the address of the terminating '\0' in
   DEST. (minor variant of strcpy) */
#define STPCPY(soname, fnname) \
   char* VG_REPLACE_FUNCTION_ZU(soname,fnname) ( char* dst, const char* src ); \
   char* VG_REPLACE_FUNCTION_ZU(soname,fnname) ( char* dst, const char* src ) \
   { \
      const Char* src_orig = src; \
            Char* dst_orig = dst; \
      \
      while (*src) *dst++ = *src++; \
      *dst = 0; \
      return dst; \
   }

STPCPY(VG_Z_LIBC_SONAME,          stpcpy)
#if defined(VGO_linux)
STPCPY(VG_Z_LIBC_SONAME,          __GI_stpcpy)
STPCPY(VG_Z_LD_LINUX_SO_2,        stpcpy)
STPCPY(VG_Z_LD_LINUX_X86_64_SO_2, stpcpy)
#endif


#define MEMSET(soname, fnname) \
   void* VG_REPLACE_FUNCTION_ZU(soname,fnname)(void *s, Int c, SizeT n); \
   void* VG_REPLACE_FUNCTION_ZU(soname,fnname)(void *s, Int c, SizeT n) \
   { \
      Addr a  = (Addr)s;   \
      UInt c4 = (c & 0xFF); \
      c4 = (c4 << 8) | c4; \
      c4 = (c4 << 16) | c4; \
      while ((a & 3) != 0 && n >= 1) \
         { *(UChar*)a = (UChar)c; a += 1; n -= 1; } \
      while (n >= 4) \
         { *(UInt*)a = c4; a += 4; n -= 4; } \
      while (n >= 1) \
         { *(UChar*)a = (UChar)c; a += 1; n -= 1; } \
      return s; \
   }

MEMSET(VG_Z_LIBC_SONAME, memset)


#define MEMMOVE(soname, fnname) \
   void* VG_REPLACE_FUNCTION_ZU(soname,fnname) \
            (void *dstV, const void *srcV, SizeT n); \
   void* VG_REPLACE_FUNCTION_ZU(soname,fnname) \
            (void *dstV, const void *srcV, SizeT n) \
   { \
      SizeT i; \
      Char* dst = (Char*)dstV; \
      Char* src = (Char*)srcV; \
      if (dst < src) { \
         for (i = 0; i < n; i++) \
            dst[i] = src[i]; \
      } \
      else  \
      if (dst > src) { \
         for (i = 0; i < n; i++) \
            dst[n-i-1] = src[n-i-1]; \
      } \
      return dst; \
   }

MEMMOVE(VG_Z_LIBC_SONAME, memmove)


/* glibc 2.5 variant of memmove which checks the dest is big enough.
   There is no specific part of glibc that this is copied from. */
#define GLIBC25___MEMMOVE_CHK(soname, fnname) \
   void* VG_REPLACE_FUNCTION_ZU(soname,fnname) \
            (void *dstV, const void *srcV, SizeT n, SizeT destlen); \
   void* VG_REPLACE_FUNCTION_ZU(soname,fnname) \
            (void *dstV, const void *srcV, SizeT n, SizeT destlen) \
   { \
      extern void _exit(int status); \
      SizeT i; \
      Char* dst = (Char*)dstV; \
      Char* src = (Char*)srcV; \
      if (destlen < n) \
         goto badness; \
      if (dst < src) { \
         for (i = 0; i < n; i++) \
            dst[i] = src[i]; \
      } \
      else  \
      if (dst > src) { \
         for (i = 0; i < n; i++) \
            dst[n-i-1] = src[n-i-1]; \
      } \
      return dst; \
     badness: \
      VALGRIND_PRINTF_BACKTRACE( \
         "*** memmove_chk: buffer overflow detected ***: " \
         "program terminated\n"); \
     _exit(127); \
     /*NOTREACHED*/ \
     return NULL; \
   }

GLIBC25___MEMMOVE_CHK(VG_Z_LIBC_SONAME, __memmove_chk)


/* Find the first occurrence of C in S or the final NUL byte.  */
#define GLIBC232_STRCHRNUL(soname, fnname) \
   char* VG_REPLACE_FUNCTION_ZU(soname,fnname) (const char* s, int c_in); \
   char* VG_REPLACE_FUNCTION_ZU(soname,fnname) (const char* s, int c_in) \
   { \
      unsigned char  c        = (unsigned char) c_in; \
      unsigned char* char_ptr = (unsigned char *)s; \
      while (1) { \
         if (*char_ptr == 0) return char_ptr; \
         if (*char_ptr == c) return char_ptr; \
         char_ptr++; \
      } \
   }

GLIBC232_STRCHRNUL(VG_Z_LIBC_SONAME, strchrnul)


/* Find the first occurrence of C in S.  */
#define GLIBC232_RAWMEMCHR(soname, fnname) \
   char* VG_REPLACE_FUNCTION_ZU(soname,fnname) (const char* s, int c_in); \
   char* VG_REPLACE_FUNCTION_ZU(soname,fnname) (const char* s, int c_in) \
   { \
      unsigned char  c        = (unsigned char) c_in; \
      unsigned char* char_ptr = (unsigned char *)s; \
      while (1) { \
         if (*char_ptr == c) return char_ptr; \
         char_ptr++; \
      } \
   }

GLIBC232_RAWMEMCHR(VG_Z_LIBC_SONAME, rawmemchr)
#if defined (VGO_linux)
GLIBC232_RAWMEMCHR(VG_Z_LIBC_SONAME, __GI___rawmemchr)
#endif

/* glibc variant of strcpy that checks the dest is big enough.
   Copied from glibc-2.5/debug/test-strcpy_chk.c. */
#define GLIBC25___STRCPY_CHK(soname,fnname) \
   char* VG_REPLACE_FUNCTION_ZU(soname,fnname) \
                               (char* dst, const char* src, SizeT len); \
   char* VG_REPLACE_FUNCTION_ZU(soname,fnname) \
                               (char* dst, const char* src, SizeT len) \
   { \
      extern void _exit(int status); \
      char* ret = dst; \
      if (! len) \
         goto badness; \
      while ((*dst++ = *src++) != '\0') \
         if (--len == 0) \
            goto badness; \
      return ret; \
     badness: \
      VALGRIND_PRINTF_BACKTRACE( \
         "*** strcpy_chk: buffer overflow detected ***: " \
         "program terminated\n"); \
     _exit(127); \
     /*NOTREACHED*/ \
     return NULL; \
   }

GLIBC25___STRCPY_CHK(VG_Z_LIBC_SONAME, __strcpy_chk)


/* glibc variant of stpcpy that checks the dest is big enough.
   Copied from glibc-2.5/debug/test-stpcpy_chk.c. */
#define GLIBC25___STPCPY_CHK(soname,fnname) \
   char* VG_REPLACE_FUNCTION_ZU(soname,fnname) \
                               (char* dst, const char* src, SizeT len); \
   char* VG_REPLACE_FUNCTION_ZU(soname,fnname) \
                               (char* dst, const char* src, SizeT len) \
   { \
      extern void _exit(int status); \
      if (! len) \
         goto badness; \
      while ((*dst++ = *src++) != '\0') \
         if (--len == 0) \
            goto badness; \
      return dst - 1; \
     badness: \
      VALGRIND_PRINTF_BACKTRACE( \
         "*** stpcpy_chk: buffer overflow detected ***: " \
         "program terminated\n"); \
     _exit(127); \
     /*NOTREACHED*/ \
     return NULL; \
   }

GLIBC25___STPCPY_CHK(VG_Z_LIBC_SONAME, __stpcpy_chk)


/* mempcpy */
#define GLIBC25_MEMPCPY(soname, fnname) \
   void* VG_REPLACE_FUNCTION_ZU(soname,fnname) \
            ( void *dst, const void *src, SizeT len ); \
   void* VG_REPLACE_FUNCTION_ZU(soname,fnname) \
            ( void *dst, const void *src, SizeT len ) \
   { \
      register char *d; \
      register char *s; \
      SizeT len_saved = len; \
      \
      if (len == 0) \
         return dst; \
      \
      if ( dst > src ) { \
         d = (char *)dst + len - 1; \
         s = (char *)src + len - 1; \
         while ( len-- ) { \
            *d-- = *s--; \
         } \
      } else if ( dst < src ) { \
         d = (char *)dst; \
         s = (char *)src; \
         while ( len-- ) { \
            *d++ = *s++; \
         } \
      } \
      return (void*)( ((char*)dst) + len_saved ); \
   }

GLIBC25_MEMPCPY(VG_Z_LIBC_SONAME, mempcpy)


#define GLIBC26___MEMCPY_CHK(soname, fnname) \
   void* VG_REPLACE_FUNCTION_ZU(soname,fnname) \
            (void* dst, const void* src, SizeT len, SizeT dstlen ); \
   void* VG_REPLACE_FUNCTION_ZU(soname,fnname) \
            (void* dst, const void* src, SizeT len, SizeT dstlen ) \
   { \
      extern void _exit(int status); \
      register char *d; \
      register char *s; \
      \
      if (dstlen < len) goto badness; \
      \
      if (len == 0) \
         return dst; \
      \
      if ( dst > src ) { \
         d = (char *)dst + len - 1; \
         s = (char *)src + len - 1; \
         while ( len-- ) { \
            *d-- = *s--; \
         } \
      } else if ( dst < src ) { \
         d = (char *)dst; \
         s = (char *)src; \
         while ( len-- ) { \
            *d++ = *s++; \
         } \
      } \
      return dst; \
     badness: \
      VALGRIND_PRINTF_BACKTRACE( \
         "*** memcpy_chk: buffer overflow detected ***: " \
         "program terminated\n"); \
     _exit(127); \
     /*NOTREACHED*/ \
     return NULL; \
   }

GLIBC26___MEMCPY_CHK(VG_Z_LIBC_SONAME, __memcpy_chk)


#define STRSTR(soname, fnname) \
   void* VG_REPLACE_FUNCTION_ZU(soname,fnname) \
         (void* haystack, void* needle); \
   void* VG_REPLACE_FUNCTION_ZU(soname,fnname) \
         (void* haystack, void* needle) \
   { \
      UChar* h = (UChar*)haystack; \
      UChar* n = (UChar*)needle; \
      \
      /* find the length of n, not including terminating zero */ \
      UWord nlen = 0; \
      while (n[nlen]) nlen++; \
      \
      /* if n is the empty string, match immediately. */ \
      if (nlen == 0) return h; \
      \
      /* assert(nlen >= 1); */ \
      UChar n0 = n[0]; \
      \
      while (1) { \
         UChar hh = *h; \
         if (hh == 0) return NULL; \
         if (hh != n0) { h++; continue; } \
         \
         UWord i; \
         for (i = 0; i < nlen; i++) { \
            if (n[i] != h[i]) \
               break; \
         } \
         /* assert(i >= 0 && i <= nlen); */ \
         if (i == nlen) \
            return h; \
         \
         h++; \
      } \
   }

#if defined(VGO_linux)
STRSTR(VG_Z_LIBC_SONAME,          strstr)
#endif


#define STRPBRK(soname, fnname) \
   void* VG_REPLACE_FUNCTION_ZU(soname,fnname) \
         (void* sV, void* acceptV); \
   void* VG_REPLACE_FUNCTION_ZU(soname,fnname) \
         (void* sV, void* acceptV) \
   { \
      UChar* s = (UChar*)sV; \
      UChar* accept = (UChar*)acceptV; \
      \
      /*  find the length of 'accept', not including terminating zero */ \
      UWord nacc = 0; \
      while (accept[nacc]) nacc++; \
      \
      /* if n is the empty string, fail immediately. */ \
      if (nacc == 0) return NULL; \
      \
      /* assert(nacc >= 1); */ \
      while (1) { \
         UWord i; \
         UChar sc = *s; \
         if (sc == 0) \
            break; \
         for (i = 0; i < nacc; i++) { \
            if (sc == accept[i]) \
               return s; \
         } \
         s++; \
      } \
      \
      return NULL; \
   }

#if defined(VGO_linux)
STRPBRK(VG_Z_LIBC_SONAME,          strpbrk)
#endif


#define STRCSPN(soname, fnname) \
   SizeT VG_REPLACE_FUNCTION_ZU(soname,fnname) \
         (void* sV, void* rejectV); \
   SizeT VG_REPLACE_FUNCTION_ZU(soname,fnname) \
         (void* sV, void* rejectV) \
   { \
      UChar* s = (UChar*)sV; \
      UChar* reject = (UChar*)rejectV; \
      \
      /* find the length of 'reject', not including terminating zero */ \
      UWord nrej = 0; \
      while (reject[nrej]) nrej++; \
      \
      UWord len = 0; \
      while (1) { \
         UWord i; \
         UChar sc = *s; \
         if (sc == 0) \
            break; \
         for (i = 0; i < nrej; i++) { \
            if (sc == reject[i]) \
               break; \
         } \
         /* assert(i >= 0 && i <= nrej); */ \
         if (i < nrej) \
            break; \
         s++; \
         len++; \
      } \
      \
      return len; \
   }

#if defined(VGO_linux)
STRCSPN(VG_Z_LIBC_SONAME,          strcspn)
#endif

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
