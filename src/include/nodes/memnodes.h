/*-------------------------------------------------------------------------
 *
 * memnodes.h
 *	  POSTGRES memory context node definitions.
 *
 *
<<<<<<< HEAD
 * Portions Copyright (c) 2007-2008, Greenplum inc
 * Portions Copyright (c) 2012-Present VMware, Inc. or its affiliates.
 * Portions Copyright (c) 1996-2021, PostgreSQL Global Development Group
=======
 * Portions Copyright (c) 1996-2023, PostgreSQL Global Development Group
>>>>>>> REL_16_9
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/nodes/memnodes.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef MEMNODES_H
#define MEMNODES_H

#include "nodes/nodes.h"

/*
 * MemoryContextCounters
 *		Summarization state for MemoryContextStats collection.
 *
 * The set of counters in this struct is biased towards AllocSet; if we ever
 * add any context types that are based on fundamentally different approaches,
 * we might need more or different counters here.  A possible API spec then
 * would be to print only nonzero counters, but for now we just summarize in
 * the format historically used by AllocSet.
 */
typedef struct MemoryContextCounters
{
	Size		nblocks;		/* Total number of malloc blocks */
	Size		freechunks;		/* Total number of free chunks */
	Size		totalspace;		/* Total bytes requested from malloc */
	Size		freespace;		/* The unused portion of totalspace */
} MemoryContextCounters;

/*
 * MemoryContext
 *		A logical context in which memory allocations occur.
 *
 * MemoryContext itself is an abstract type that can have multiple
 * implementations.
 * The function pointers in MemoryContextMethods define one specific
 * implementation of MemoryContext --- they are a virtual function table
 * in C++ terms.
 *
 * Node types that are actual implementations of memory contexts must
 * begin with the same fields as MemoryContextData.
 *
 * Note: for largely historical reasons, typedef MemoryContext is a pointer
 * to the context struct rather than the struct type itself.
 */

typedef void (*MemoryStatsPrintFunc) (MemoryContext context, void *passthru,
									  const char *stats_string,
									  bool print_to_stderr);

typedef struct MemoryContextMethods
{
	void	   *(*alloc) (MemoryContext context, Size size);
	/* call this free_p in case someone #define's free() */
	void		(*free_p) (void *pointer);
	void	   *(*realloc) (void *pointer, Size size);
	void		(*reset) (MemoryContext context);
<<<<<<< HEAD
	void		(*delete_context) (MemoryContext context, MemoryContext parent);
	Size		(*get_chunk_space) (MemoryContext context, void *pointer);
=======
	void		(*delete_context) (MemoryContext context);
	MemoryContext (*get_chunk_context) (void *pointer);
	Size		(*get_chunk_space) (void *pointer);
>>>>>>> REL_16_9
	bool		(*is_empty) (MemoryContext context);
	void		(*stats) (MemoryContext context,
						  MemoryStatsPrintFunc printfunc, void *passthru,
						  MemoryContextCounters *totals,
						  bool print_to_stderr);
	void		(*declare_accounting_root) (MemoryContext context);
	Size		(*get_current_usage) (MemoryContext context);
	Size		(*get_peak_usage) (MemoryContext context);
	Size		(*set_peak_usage) (MemoryContext context, Size nbytes);

#ifdef MEMORY_CONTEXT_CHECKING
	void		(*check) (MemoryContext context);
#endif
} MemoryContextMethods;


typedef struct MemoryContextData
{
	pg_node_attr(abstract)		/* there are no nodes of this type */

	NodeTag		type;			/* identifies exact kind of context */
	/* these two fields are placed here to minimize alignment wastage: */
	bool		isReset;		/* T = no space alloced since last reset */
	bool		allowInCritSection; /* allow palloc in critical section */
	Size		mem_allocated;	/* track memory allocated for this context */
	const MemoryContextMethods *methods;	/* virtual function table */
	MemoryContext parent;		/* NULL if no parent (toplevel context) */
	MemoryContext firstchild;	/* head of linked list of children */
	MemoryContext prevchild;	/* previous child of same parent */
	MemoryContext nextchild;	/* next child of same parent */
	const char *name;			/* context name (just for debugging) */
	const char *ident;			/* context ID if any (just for debugging) */

#ifdef CDB_PALLOC_CALLER_ID
    const char *callerFile;     /* __FILE__ of most recent caller */
    int         callerLine;     /* __LINE__ of most recent caller */
#endif

	MemoryContextCallback *reset_cbs;	/* list of reset/delete callbacks */
} MemoryContextData;

/* utils/palloc.h contains typedef struct MemoryContextData *MemoryContext */


/*
 * MemoryContextIsValid
 *		True iff memory context is valid.
 *
 * Add new context types to the set accepted by this macro.
 */
#define MemoryContextIsValid(context) \
	((context) != NULL && \
	 (IsA((context), AllocSetContext) || \
	  IsA((context), SlabContext) || \
	  IsA((context), GenerationContext)))

#endif							/* MEMNODES_H */
