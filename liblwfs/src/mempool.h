/*************************************************************************
 *                                                                       *
 * (c) 2009 Wolf Software Limited <mempool@wolf-software.net>            *
 * All Rights Reserved.                                                  *
 *                                                                       *
 * This program is free software: you can redistribute it and/or modify  *
 * it under the terms of the GNU General Public License as published by  *
 * the Free Software Foundation, either version 3 of the License, or     *
 * (at your option) any later version.                                   *
 *                                                                       *
 * This program is distributed in the hope that it will be useful,       *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 * GNU General Public License for more details.                          *
 *                                                                       *
 * You should have received a copy of the GNU General Public License     *
 * along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 *                                                                       *
 *************************************************************************/

/*********************************************************************//**
 @file mempool.h
 @brief The library header file.
 *************************************************************************/
//#define LIXI_MEMPOOL 1
 
#ifndef __LIBMEMPOOL_H__
#define __LIBMEMPOOL_H__

#ifdef  __cplusplus
extern "C" {
#endif

/*********************************************************************//**
 @brief The structure that points to the actually allocated memory.
 *************************************************************************/

typedef struct mempool_entry_struct
{
  void                        *data;            /*!< The actual memory allocated. */

  const char                  *file;            /*!< Filename. */
  int                          line;            /*!< Line Number. */
  const char                  *function;        /*!< Function name. */

  struct mempool_entry_struct *prev;            /*!< A pointer to the previous element. */
  struct mempool_entry_struct *next;            /*!< A pointer to the next element. */
  struct mempool_entry_struct *tail;            /*!< A pointer to the tail of the list. */

} mempool_entry;

/*********************************************************************//**
 @brief The structure that handles individual tables.
 *************************************************************************/

typedef struct mempool_table_struct
{
  int                          size;            /*!< The size of the table (always a power of 2). */
  int                          total_count;     /*!< Total number of blocks in the table. */
  int                          used_count;      /*!< Number of used blocks in the table. */
  int                          free_count;      /*!< Number of free blocks in the table. */
  int                          pre_allocated;   /*!< Number of pre-allocated blocks in the table. */
  int                          allocated;       /*!< Number of blocks added during run time. */
  int                          max_used;        /*!< Maximum number of blocks in use at any one time */

  struct mempool_table_struct *next;            /*!< A pointer to the previous element. */
  struct mempool_table_struct *prev;            /*!< A pointer to the next element. */
  struct mempool_table_struct *tail;            /*!< A pointer to the tail of the list. */

  mempool_entry               *free_list;       /*!< A pointer to the start of the list of free blocks. */
  mempool_entry               *free_tail;       /*!< A pointer to the tail of the list of free blocks. */

  mempool_entry               *used_list;       /*!< A pointer to the start of the list of used blocks. */
  mempool_entry               *used_tail;       /*!< A pointer to the tail of the list of used blocks. */

} mempool_table;

/*********************************************************************//**
 @brief The top level mempool structure.
 *************************************************************************/

typedef struct mempool_struct
{
  int                         smallest_block;   /*!< The size of the smallest block that will be allocated. */
  int                         largest_block;    /*!< The size of the largest block that will be allocated. */

  mempool_table               *table;           /*!< A pointer to the first table in the list. */
} mempool;

/*********************************************************************//**
 @brief The pre-allocation structure.
 *************************************************************************/

typedef struct mempool_preallocate_list_struct
{
  int                          size;           /*!< The size of the table (memory block). */
  int                          count;          /*!< The number of blocks to pre-allocate. */
} mempool_preallocate_list;

extern int      mempool_debug;

extern mempool *create_mempool        ( int smallest_block, int largest_block );
extern int      destroy_mempool       ( mempool **pool );

extern void    *mempool_malloc        ( mempool *pool, size_t request_size );
extern void    *mempool_calloc        ( mempool *pool, size_t count, size_t request_size );
extern void    *mempool_realloc       ( mempool *pool, void *ptr, size_t request_size );
extern char    *mempool_strdup        ( mempool *pool, const char *str );

extern void    *mempool_malloc_debug  ( mempool *pool, size_t request_size, const char *file, const char *function, int line );
extern void    *mempool_calloc_debug  ( mempool *pool, size_t count, size_t request_size, const char *file, const char *function, int line );
extern void    *mempool_realloc_debug ( mempool *pool, void *ptr, size_t request_size, const char *file, const char *function, int line );
extern char    *mempool_strdup_debug  ( mempool *pool, const char *str, const char *file, const char *function, int line );

extern void     mempool_free          ( mempool *pool, void *ptr );
extern void     mempool_preallocate   ( mempool **pool, mempool_preallocate_list preallocate_list[] );

#ifdef  __cplusplus
}
#endif

#endif /* __LIBMEMPOOL_H__ */

/* EOF */
