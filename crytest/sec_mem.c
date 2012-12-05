/****************************************************************************
*																			*
*							Secure Memory Management						*
*						Copyright Peter Gutmann 1995-2007					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "acl.h"
  #include "kernel.h"
#else
  #include "crypt.h"
  #include "kernel/acl.h"
  #include "kernel/kernel.h"
#endif /* Compiler-specific includes */

/* A pointer to the kernel data block */

static KERNEL_DATA *krnlData = NULL;

/* The minimum and maximum amount of secure memory that we can ever allocate.
   A more normal upper bound is 8K, however the SSL session cache constitutes
   a single large chunk of secure memory that goes way over this limit */

#define MIN_ALLOC_SIZE			8
#define MAX_ALLOC_SIZE			8192

/* To support page locking we need to store some additional information with
   the memory block.  We do this by reserving an extra memory block at the
   start of the allocated block and saving the information there.

   The information stored in the extra block is a flag indicating whether the
   block is pagelocked (so we can call the unlock function when we free it),
   the size of the block, and pointers to the next and previous pointers in
   the list of allocated blocks (this is used by the thread that walks the
   block list touching each one) */

#define CANARY_SIZE		4		/* Size of canary used to spot overwrites */

typedef struct {
	BOOLEAN isLocked;			/* Whether this block is locked */
	int size;					/* Size of the block (including the size
								   of the MEMLOCK_INFO) */
	void *next, *prev;			/* Next, previous memory block */
#if defined( __BEOS__ )
	area_id areaID;				/* Needed for page locking under BeOS */
#endif /* BeOS and BeOS areas */
	BYTE canary[ CANARY_SIZE ];	/* Canary for spotting overwrites */
	} MEMLOCK_INFO;

#if INT_MAX <= 32767
  #define MEMLOCK_HEADERSIZE	roundUp( sizeof( MEMLOCK_INFO ), 4 )
#elif INT_MAX <= 0xFFFFFFFFUL
  #define MEMLOCK_HEADERSIZE	roundUp( sizeof( MEMLOCK_INFO ), 8 )
#else
  #define MEMLOCK_HEADERSIZE	roundUp( sizeof( MEMLOCK_INFO ), 16 )
#endif /* 16/32/64-bit systems */

/* We also insert a canary at the start and end of each block to detect 
   memory overwrites, the block size is adjusted accordingly to handle this 
   extra data */

#define CANARY_STARTVALUE	"\xC0\xED\xBA\xBE"	/* More fun than dead beef */
#define CANARY_ENDVALUE		"\x36\xDD\x24\x36"

#define adjustMemCanary( size ) \
		size += CANARY_SIZE	/* Other canary is in MEMLOCK_INFO header */
#define insertMemCanary( memBlockPtr, memPtr ) \
		memcpy( memBlockPtr->canary, CANARY_STARTVALUE, CANARY_SIZE ); \
		memcpy( memPtr + memBlockPtr->size - CANARY_SIZE, CANARY_ENDVALUE, \
				CANARY_SIZE )
#define checkMemCanary( memBlockPtr, memPtr ) \
		REQUIRES( !memcmp( memBlockPtr->canary, CANARY_STARTVALUE, CANARY_SIZE ) ); \
		REQUIRES( !memcmp( memPtr + memBlockPtr->size - CANARY_SIZE, \
						   CANARY_ENDVALUE, CANARY_SIZE ) );

/****************************************************************************
*																			*
*								Misc Functions								*
*																			*
****************************************************************************/

/* Prepare to allocate/free a block of secure memory */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkInitAlloc( OUT void **allocPtrPtr, 
						   IN_RANGE( MIN_ALLOC_SIZE, MAX_ALLOC_SIZE ) \
							const int size )
	{
	static_assert( MEMLOCK_HEADERSIZE >= sizeof( MEMLOCK_INFO ), \
				   "Memlock header size" );

	/* Make sure that the parameters are in order */
	if( !isWritePtrConst( allocPtrPtr, sizeof( void * ) ) )
		retIntError();
	
	REQUIRES( size >= MIN_ALLOC_SIZE && size <= MAX_ALLOC_SIZE );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int checkInitFree( const void **freePtrPtr, 
						  OUT_OPT_PTR BYTE **memPtrPtr, 
						  OUT_OPT_PTR MEMLOCK_INFO **memBlockPtrPtr )
	{
	MEMLOCK_INFO *memBlockPtr;
	BYTE *memPtr;

	assert( isWritePtr( memPtrPtr, sizeof( BYTE * ) ) );
	assert( isWritePtr( memBlockPtrPtr, sizeof( MEMLOCK_INFO * ) ) );

	/* Make sure that the parameters are in order */
	if( !isReadPtrConst( freePtrPtr, sizeof( void * ) ) || \
		!isReadPtrConst( *freePtrPtr, MIN_ALLOC_SIZE ) )
		retIntError();

	/* Clear return values */
	*memPtrPtr = NULL;
	*memBlockPtrPtr = NULL;

	/* Recover the actual allocated memory block data from the pointer */
	memPtr = ( ( BYTE * ) *freePtrPtr ) - MEMLOCK_HEADERSIZE;
	if( !isReadPtrConst( memPtr, sizeof( MEMLOCK_INFO ) ) )
		retIntError();
	memBlockPtr = ( MEMLOCK_INFO * ) memPtr;
	REQUIRES( memBlockPtr->size >= sizeof( MEMLOCK_INFO ) + MIN_ALLOC_SIZE && \
			  memBlockPtr->size <= sizeof( MEMLOCK_INFO ) + MAX_ALLOC_SIZE && \
			  ( memBlockPtr->isLocked == FALSE || \
				memBlockPtr->isLocked == TRUE ) );

	*memPtrPtr = memPtr;
	*memBlockPtrPtr = memBlockPtr;
	return( CRYPT_OK );
	}

/* Insert and unlink a memory block from a list of memory blocks.  We can't 
   use insertDoubleListElements()/deleteDoubleListElement() for this because 
   they don't handle the end-of-list pointer, since they're intended for 
   random-access lists rather than append-only lists */

STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static void insertMemBlock( INOUT MEMLOCK_INFO **allocatedListHeadPtr, 
							INOUT MEMLOCK_INFO **allocatedListTailPtr, 
							INOUT MEMLOCK_INFO *memBlockPtr )
	{
	MEMLOCK_INFO *allocatedListHead = *allocatedListHeadPtr;
	MEMLOCK_INFO *allocatedListTail = *allocatedListTailPtr;

	assert( isWritePtr( allocatedListHeadPtr, sizeof( MEMLOCK_INFO * ) ) );
	assert( allocatedListHead == NULL || \
			isWritePtr( allocatedListHead, sizeof( MEMLOCK_INFO ) ) );
	assert( isWritePtr( allocatedListTailPtr, sizeof( MEMLOCK_INFO * ) ) );
	assert( allocatedListTail == NULL || \
			isWritePtr( allocatedListTail, sizeof( MEMLOCK_INFO ) ) );
	assert( isWritePtr( memBlockPtr, sizeof( MEMLOCK_INFO * ) ) );

	REQUIRES_V( ( allocatedListHead == NULL && \
				  allocatedListTail == NULL ) || \
				( allocatedListHead != NULL && \
				  allocatedListTail != NULL ) );

	/* If it's a new list, set up the head and tail pointers and return */
	if( allocatedListHead == NULL )
		{
		*allocatedListHeadPtr = *allocatedListTailPtr = memBlockPtr;
		return;
		}

	/* It's an existing list, add the new element to the end */
	allocatedListTail->next = memBlockPtr;
	memBlockPtr->prev = allocatedListTail;
	*allocatedListTailPtr = memBlockPtr;
	}

STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static void unlinkMemBlock( INOUT MEMLOCK_INFO **allocatedListHeadPtr, 
							INOUT MEMLOCK_INFO **allocatedListTailPtr, 
							INOUT MEMLOCK_INFO *memBlockPtr )
	{
	MEMLOCK_INFO *allocatedListHead = *allocatedListHeadPtr;
	MEMLOCK_INFO *allocatedListTail = *allocatedListTailPtr;
	MEMLOCK_INFO *nextBlockPtr = memBlockPtr->next;
	MEMLOCK_INFO *prevBlockPtr = memBlockPtr->prev;

	assert( isWritePtr( allocatedListHeadPtr, sizeof( MEMLOCK_INFO * ) ) );
	assert( allocatedListHead == NULL || \
			isWritePtr( allocatedListHead, sizeof( MEMLOCK_INFO ) ) );
	assert( isWritePtr( allocatedListTailPtr, sizeof( MEMLOCK_INFO * ) ) );
	assert( allocatedListTail == NULL || \
			isWritePtr( allocatedListTail, sizeof( MEMLOCK_INFO ) ) );
	assert( isWritePtr( memBlockPtr, sizeof( MEMLOCK_INFO * ) ) );

	/* If we're removing the block from the start of the list, make the
	   start the next block */
	if( memBlockPtr == allocatedListHead )
		*allocatedListHeadPtr = nextBlockPtr;
	else
		{
		REQUIRES_V( prevBlockPtr != NULL );

		/* Delete from the middle or end of the list */
		prevBlockPtr->next = nextBlockPtr;
		}
	if( nextBlockPtr != NULL )
		nextBlockPtr->prev = prevBlockPtr;

	/* If we're removed the last element, update the end pointer */
	if( memBlockPtr == allocatedListTail )
		*allocatedListTailPtr = prevBlockPtr;

	/* Clear the current block's pointers, just to be clean */
	memBlockPtr->next = memBlockPtr->prev = NULL;
	}

#if 0	/* Currently unused, in practice would be called from a worker thread
		   that periodically touches all secure-data pages */

/* Walk the allocated block list touching each page.  In most cases we don't
   need to explicitly touch the page since the allocated blocks are almost
   always smaller than the MMU's page size and simply walking the list
   touches them, but in some rare cases we need to explicitly touch each
   page */

static void touchAllocatedPages( void )
	{
	MEMLOCK_INFO *memBlockPtr;

	/* Lock the allocation object to ensure that other threads don't try to
	   access them */
	MUTEX_LOCK( allocation );

	/* Walk down the list (which implicitly touches each page).  If the
	   allocated region is larger than 4K, explicitly touch each 4K page.
	   This assumes a page size of 4K which is usually true (and difficult
	   to determine otherwise), in any case it doesn't make much difference
	   since nothing ever allocates more than two 4K pages */
	for( memBlockPtr = krnlData->allocatedListHead; memBlockPtr != NULL;
		 memBlockPtr = memBlockPtr->next )
		{
		const int pageSize = getSysVar( SYSVAR_PAGESIZE );

		/* If the allocated region has pages beyond the first one (which 
		   we've already touched by accessing the header), explicitly
		   touch those pages as well */
		if( memBlockPtr->size > pageSize )
			{
			BYTE *memPtr = ( BYTE * ) memBlockPtr + pageSize;
			int memSize = memBlockPtr->size;

			/* Touch each page.  The rather convoluted expression is to try
			   and stop it from being optimised away - it always evaluates to
			   true since we only get here if allocatedListHead != NULL, but
			   hopefully the compiler won't be able to figure that out */
			while( memSize > pageSize )
				{
				if( *memPtr || krnlData->allocatedListHead != NULL )
					memPtr += pageSize;
				memSize -= pageSize;
				}
			}
		}

	/* Unlock the allocation object to allow access by other threads */
	MUTEX_UNLOCK( allocation );
	}
#endif /* 0 */

/****************************************************************************
*																			*
*							Init/Shutdown Functions							*
*																			*
****************************************************************************/

/* Create and destroy the secure allocation information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initAllocation( INOUT KERNEL_DATA *krnlDataPtr )
	{
	int status;

	assert( isWritePtr( krnlDataPtr, sizeof( KERNEL_DATA ) ) );

	/* Set up the reference to the kernel data block */
	krnlData = krnlDataPtr;

	/* Clear the list head and tail pointers */
	krnlData->allocatedListHead = krnlData->allocatedListTail = NULL;

	/* Initialize any data structures required to make the allocation thread-
	   safe */
	MUTEX_CREATE( allocation, status );
	ENSURES( cryptStatusOK( status ) );

	return( CRYPT_OK );
	}

void endAllocation( void )
	{
	/* Destroy any data structures required to make the allocation thread-
	   safe */
	MUTEX_DESTROY( allocation );

	krnlData = NULL;
	}

/****************************************************************************
*																			*
*					Windows Secure Memory Allocation Functions				*
*																			*
****************************************************************************/

#if defined( __WIN32__ )

#if !defined( NDEBUG ) && !defined( NT_DRIVER ) && !defined( __BORLANDC__ )
  #define USE_HEAP_CHECKING
#endif /* Win32 debug version */

#ifdef USE_HEAP_CHECKING
  #include <crtdbg.h>	/* For heap checking in debug version */
#endif /* USE_HEAP_CHECKING */

/* Get the start address of a page and, given an address in a page and a
   size, determine on which page the data ends.  These are used to determine
   which pages a memory block covers */

#if defined( _MSC_VER ) && ( _MSC_VER >= 1400 )
  #define PTR_TYPE	INT_PTR 
#else
  #define PTR_TYPE	long
#endif /* Newer versions of VC++ */

#define getPageStartAddress( address ) \
			( ( PTR_TYPE ) ( address ) & ~( pageSize - 1 ) )
#define getPageEndAddress( address, size ) \
			getPageStartAddress( ( PTR_TYPE ) address + ( size ) - 1 )

/* A safe malloc function that performs page locking if possible */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int krnlMemalloc( OUT_BUFFER_ALLOC_OPT( size ) void **pointer, 
				  IN_LENGTH int size )
	{
	MEMLOCK_INFO *memBlockPtr;
	BYTE *memPtr;
	int status;

	status = checkInitAlloc( pointer, size );
	if( cryptStatusError( status ) )
		return( status );
	
	/* Clear return values */
	*pointer = NULL;

	/* Try and allocate the memory */
	adjustMemCanary( size );	/* For canary at end of block */
	if( ( memPtr = clAlloc( "krnlMemAlloc", \
							size + MEMLOCK_HEADERSIZE ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( memPtr, 0, size + MEMLOCK_HEADERSIZE );
	memBlockPtr = ( MEMLOCK_INFO * ) memPtr;
	memBlockPtr->isLocked = FALSE;
	memBlockPtr->size = size + MEMLOCK_HEADERSIZE;
	insertMemCanary( memBlockPtr, memPtr );
	*pointer = memPtr + MEMLOCK_HEADERSIZE;

	/* Try to lock the pages in memory */
#if !defined( NT_DRIVER )
	/* Under Win95 the VirtualLock() function is implemented as
	   `return( TRUE )' ("Thank Microsoft kids" - "Thaaaanks Bill").  Under
	   NT the function does actually work, but with a number of caveats.
	   The main one is that it has been claimed that VirtualLock() only
	   guarantees that the memory won't be paged while a thread in the
	   process is running, and when all threads are preempted the memory is
	   still a target for paging.  This would mean that on a loaded system a
	   process that was idle for some time could have the memory unlocked by
	   the system and swapped out to disk (actually with NT's somewhat
	   strange paging strategy and gradual creeping takeover of free memory
	   for disk buffers, it can get paged even on a completely unloaded
	   system).  However, attempts to force data to be paged under Win2K
	   and XP under various conditions have been unsuccesful so it may be
	   that the behaviour changed in post-NT versions of the OS.  In any
	   case VirtualLock() under these newer OSes seems to be fairly
	   effective in keeping data off disk.

	   An additional concern is that although VirtualLock() takes arbitrary
	   memory pointers and a size parameter, the locking is actually done on
	   a per-page basis, so that unlocking a region that shares a page with
	   another locked region means that both reqions are unlocked.  Since
	   VirtualLock() doesn't do reference counting (emulating the underlying
	   MMU page locking even though it seems to implement an intermediate
	   layer above the MMU so it could in theory do this), the only way
	   around this is to walk the chain of allocated blocks and not unlock a
	   block if there's another block allocated on the same page.  Ick.

	   For the NT kernel driver, the memory is always allocated from the non-
	   paged pool so there's no need for these gyrations */
	if( VirtualLock( memPtr, memBlockPtr->size ) )
		memBlockPtr->isLocked = TRUE;
#endif /* !NT_DRIVER */

	/* Lock the memory list, insert the new block, and unlock it again */
	MUTEX_LOCK( allocation );
	insertMemBlock( ( MEMLOCK_INFO ** ) &krnlData->allocatedListHead, 
					( MEMLOCK_INFO ** ) &krnlData->allocatedListTail, 
					memBlockPtr );
#ifdef USE_HEAP_CHECKING
	/* Sanity check to detect memory chain corruption */
	assert( _CrtIsValidHeapPointer( memBlockPtr ) );
	assert( memBlockPtr->next == NULL );
	assert( krnlData->allocatedListHead == krnlData->allocatedListTail || \
			_CrtIsValidHeapPointer( memBlockPtr->prev ) );
#endif /* USE_HEAP_CHECKING */
	MUTEX_UNLOCK( allocation );

	return( CRYPT_OK );
	}

/* A safe free function that scrubs memory and zeroes the pointer.

	"You will softly and suddenly vanish away
	 And never be met with again"	- Lewis Carroll,
									  "The Hunting of the Snark" */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int krnlMemfree( INOUT_PTR void **pointer )
	{
	MEMLOCK_INFO *memBlockPtr;
	BYTE *memPtr;
	int status;

	/* Check the function preconditions */
	status = checkInitFree( pointer, &memPtr, &memBlockPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* Lock the memory list, unlink the new block, and unlock it again */
	MUTEX_LOCK( allocation );
	checkMemCanary( memBlockPtr, memPtr );
#ifdef USE_HEAP_CHECKING
	/* Sanity check to detect memory chain corruption */
	assert( _CrtIsValidHeapPointer( memBlockPtr ) );
	assert( memBlockPtr->next == NULL || \
			_CrtIsValidHeapPointer( memBlockPtr->next ) );
	assert( memBlockPtr->prev == NULL || \
			_CrtIsValidHeapPointer( memBlockPtr->prev ) );
#endif /* USE_HEAP_CHECKING */
	unlinkMemBlock( ( MEMLOCK_INFO ** ) &krnlData->allocatedListHead, 
					( MEMLOCK_INFO ** ) &krnlData->allocatedListTail, 
					memBlockPtr );
#if !defined( NT_DRIVER )
	/* Because VirtualLock() works on a per-page basis, we can't unlock a
	   memory block if there's another locked block on the same page.  The
	   only way to manage this is to walk the block list checking to see
	   whether there's another block allocated on the same page.  Although in
	   theory this could make freeing memory rather slow, in practice there
	   are only a small number of allocated blocks to check so it's
	   relatively quick, especially compared to the overhead imposed by the
	   lethargic VC++ allocator.  The only real disadvantage is that the
	   allocation objects remain locked while we do the free, but this
	   isn't any worse than the overhead of touchAllocatedPages().  Note 
	   that the following code assumes that an allocated block will never 
	   cover more than two pages, which is always the case */
	if( memBlockPtr->isLocked )
		{
		MEMLOCK_INFO *currentBlockPtr;
		PTR_TYPE block1PageAddress, block2PageAddress;
		const int pageSize = getSysVar( SYSVAR_PAGESIZE );

		/* Calculate the addresses of the page(s) in which the memory block
		   resides */
		block1PageAddress = getPageStartAddress( memBlockPtr );
		block2PageAddress = getPageEndAddress( memBlockPtr, memBlockPtr->size );
		if( block1PageAddress == block2PageAddress )
			block2PageAddress = 0;

		/* Walk down the block list checking whether the page(s) contain
		   another locked block */
		for( currentBlockPtr = krnlData->allocatedListHead; \
			 currentBlockPtr != NULL; currentBlockPtr = currentBlockPtr->next )
			{
			const PTR_TYPE currentPage1Address = \
						getPageStartAddress( currentBlockPtr );
			PTR_TYPE currentPage2Address = \
						getPageEndAddress( currentBlockPtr, currentBlockPtr->size );

			if( currentPage1Address == currentPage2Address )
				currentPage2Address = 0;

			/* There's another block allocated on either of the pages, don't
			   unlock it */
			if( block1PageAddress == currentPage1Address || \
				block1PageAddress == currentPage2Address )
				{
				block1PageAddress = 0;
				if( !block2PageAddress )
					break;
				}
			if( block2PageAddress == currentPage1Address || \
				block2PageAddress == currentPage2Address )
				{
				block2PageAddress = 0;
				if( !block1PageAddress )
					break;
				}
			}

		/* Finally, if either page needs unlocking, do so.  The supplied size
		   is irrelevant since the entire page the memory is on is unlocked */
		if( block1PageAddress )
			VirtualUnlock( ( void * ) block1PageAddress, 16 );
		if( block2PageAddress )
			VirtualUnlock( ( void * ) block2PageAddress, 16 );
		}
#endif /* !NT_DRIVER */
	MUTEX_UNLOCK( allocation );

	/* Zeroise the memory (including the memlock info), free it, and zero
	   the pointer */
	zeroise( memPtr, memBlockPtr->size );
	clFree( "krnlMemFree", memPtr );
	*pointer = NULL;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					Unix/BeOS Secure Memory Allocation Functions			*
*																			*
****************************************************************************/

#elif defined( __UNIX__ ) || defined( __BEOS__ )

/* Since the function prototypes for the SYSV/Posix mlock() call are stored
   all over the place depending on the Unix version, we usually have to
   prototype it ourselves here rather than trying to guess its location */

#if defined( __osf__ ) || defined( __alpha__ )
  #include <sys/mman.h>
#elif defined( sun )
  #include <sys/mman.h>
  #include <sys/types.h>
#else
  int mlock( void *address, size_t length );
  int munlock( void *address, size_t length );
#endif /* Unix-variant-specific includes */

/* Under many Unix variants the SYSV/Posix mlock() call can be used, but 
   only by the superuser (with occasional OS-specific variants, for example 
   under some newer Linux variants the caller needs the specific 
   CAP_IPC_LOCK privilege rather than just generally being root).  OSF/1 has 
   mlock(), but this is defined to the nonexistant memlk() so we need to 
   special-case it out.  QNX (depending on the version) either doesn't have 
   mlock() at all or it's a dummy that just returns -1, so we no-op it out.  
   Aches, A/UX, PHUX, Linux < 1.3.something, and Ultrix don't even pretend 
   to have mlock().  Many systems also have plock(), but this is pretty 
   crude since it locks all data, and also has various other shortcomings.  
   Finally, PHUX has datalock(), which is just a plock() variant */

#if defined( _AIX ) || defined( __alpha__ ) || defined( __aux ) || \
	defined( _CRAY ) || defined( __CYGWIN__ ) || defined( __hpux ) || \
	( defined( __linux__ ) && OSVERSION < 2 ) || \
	defined( _M_XENIX ) || defined( __osf__ ) || \
	( defined( __QNX__ ) && OSVERSION <= 6 ) || \
	defined( __TANDEM_NSK__ ) || defined( __TANDEM_OSS__ ) || \
	defined( __ultrix )
  #define mlock( a, b )		1
  #define munlock( a, b )
#endif /* Unix OS-specific defines */

/* A safe malloc function that performs page locking if possible */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int krnlMemalloc( OUT_BUFFER_ALLOC_OPT( size ) void **pointer, 
				  IN_LENGTH int size )
	{
	MEMLOCK_INFO *memBlockPtr;
	BYTE *memPtr;
#if defined( __BEOS__ )
	area_id areaID;
#endif /* __BEOS__ && BeOS areas */
	int status;

	status = checkInitAlloc( pointer, size );
	if( cryptStatusError( status ) )
		return( status );

	/* Clear return values */
	*pointer = NULL;

	/* Try and allocate the memory */
	adjustMemCanary( size );	/* For canary at end of block */
#if defined( __BEOS__ )
	/* Under BeOS we have to allocate a locked area, we can't lock it after
	   the event.  create_area(), like most of the low-level memory access
	   functions provided by different OSes, functions at the page level, so
	   we round the size up to the page size.  We can mitigate the
	   granularity somewhat by specifying lazy locking, which means that the
	   page isn't locked until it's committed.

	   In pre-open-source BeOS, areas were bit of a security tradeoff because
	   they were globally visible(!!!) through the use of find_area(), so
	   that any other process in the system could find them.  An attacker
	   could always find the app's malloc() arena anyway because of this,
	   but putting data directly into areas made the attacker's task
	   somewhat easier.  Open-source BeOS fixed this, mostly because it
	   would have taken extra work to make areas explicitly globally visible
	   and no-one could see a reason for this, so it's somewhat safer there.

	   However, the implementation of create_area() in the open-source BeOS
	   seems to be rather flaky (simply creating an area and then
	   immediately destroying it again causes a segmentation violation) so
	   it may be necessary to turn it off for some BeOS releases */
	areaID = create_area( "memory_block", ( void ** ) &memPtr, B_ANY_ADDRESS,
						  roundUp( size + MEMLOCK_HEADERSIZE, B_PAGE_SIZE ),
						  B_LAZY_LOCK, B_READ_AREA | B_WRITE_AREA );
	if( areaID < B_NO_ERROR )
#else
	if( ( memPtr = clAlloc( "krnlMemAlloc", \
							size + MEMLOCK_HEADERSIZE ) ) == NULL )
#endif /* __BEOS__ */
		return( CRYPT_ERROR_MEMORY );
	memset( memPtr, 0, size + MEMLOCK_HEADERSIZE );
	memBlockPtr = ( MEMLOCK_INFO * ) memPtr;
	memBlockPtr->isLocked = FALSE;
	memBlockPtr->size = size + MEMLOCK_HEADERSIZE;
#if defined( __BEOS__ )
	memBlockPtr->areaID = areaID;
#endif /* __BEOS__ && BeOS areas */
	insertMemCanary( memBlockPtr, memPtr );
	*pointer = memPtr + MEMLOCK_HEADERSIZE;

	/* Try to lock the pages in memory */
#if !defined( __BEOS__ )
	if( !mlock( memPtr, memBlockPtr->size ) )
		memBlockPtr->isLocked = TRUE;
#endif /* !__BEOS__ */

	/* Lock the memory list, insert the new block, and unlock it again */
	MUTEX_LOCK( allocation );
	insertMemBlock( ( MEMLOCK_INFO ** ) &krnlData->allocatedListHead, 
					( MEMLOCK_INFO ** ) &krnlData->allocatedListTail, 
					memBlockPtr );
	MUTEX_UNLOCK( allocation );

	return( CRYPT_OK );
	}

/* A safe free function that scrubs memory and zeroes the pointer.

	"You will softly and suddenly vanish away
	 And never be met with again"	- Lewis Carroll,
									  "The Hunting of the Snark" */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int krnlMemfree( INOUT_PTR void **pointer )
	{
	MEMLOCK_INFO *memBlockPtr;
	BYTE *memPtr;
#if defined( __BEOS__ )
	area_id areaID;
#endif /* __BEOS__ && BeOS areas */
	int status;

	/* Check the function preconditions */
	status = checkInitFree( ( const void ** ) pointer, &memPtr, 
							&memBlockPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* Lock the memory list, unlink the new block, and unlock it again */
	MUTEX_LOCK( allocation );
	checkMemCanary( memBlockPtr, memPtr );
	unlinkMemBlock( ( MEMLOCK_INFO ** ) &krnlData->allocatedListHead, 
					( MEMLOCK_INFO ** ) &krnlData->allocatedListTail, 
					memBlockPtr );
	MUTEX_UNLOCK( allocation );

	/* If the memory was locked, unlock it now */
#if defined( __BEOS__ )
	areaID = memBlockPtr->areaID;
	zeroise( memPtr, memBlockPtr->size );
	delete_area( areaID );
#else
	if( memBlockPtr->isLocked )
		munlock( memPtr, memBlockPtr->size );
#endif /* OS-specific memory unlocking */

	/* Zeroise the memory (including the memlock info), free it, and zero
	   the pointer */
#if !defined( __BEOS__ )
	zeroise( memPtr, memBlockPtr->size );
	clFree( "krnlMemFree", memPtr );
#endif /* !__BEOS__ */
	*pointer = NULL;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					ChorusOS Secure Memory Allocation Functions				*
*																			*
****************************************************************************/

#elif defined( __CHORUS__ )

/* ChorusOS is one of the very few embedded OSes with paging capabilities,
   fortunately there's a way to allocate nonpageable memory if paging is
   enabled */

#include <mem/chMem.h>

/* A safe malloc function that performs page locking if possible */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int krnlMemalloc( OUT_BUFFER_ALLOC_OPT( size ) void **pointer, 
				  IN_LENGTH int size )
	{
	MEMLOCK_INFO *memBlockPtr;
	BYTE *memPtr;
	KnRgnDesc rgnDesc = { K_ANYWHERE, size + MEMLOCK_HEADERSIZE, \
						  K_WRITEABLE | K_NODEMAND };
	int status;

	status = checkInitAlloc( pointer, size );
	if( cryptStatusError( status ) )
		return( status );

	/* Clear return values */
	*pointer = NULL;

	/* Try and allocate the memory */
	adjustMemCanary( size );	/* For canary at end of block */
	if( rgnAllocate( K_MYACTOR, &rgnDesc ) != K_OK )
		return( CRYPT_ERROR_MEMORY );
	memPtr = rgnDesc.startAddr;
	memset( memPtr, 0, size + MEMLOCK_HEADERSIZE );
	memBlockPtr = ( MEMLOCK_INFO * ) memPtr;
	memBlockPtr->isLocked = FALSE;
	memBlockPtr->size = size + MEMLOCK_HEADERSIZE;
	insertMemCanary( memBlockPtr, memPtr );
	*pointer = memPtr + MEMLOCK_HEADERSIZE;

	/* Lock the memory list, insert the new block, and unlock it again */
	MUTEX_LOCK( allocation );
	insertMemBlock( ( MEMLOCK_INFO ** ) &krnlData->allocatedListHead, 
					( MEMLOCK_INFO ** ) &krnlData->allocatedListTail, 
					memBlockPtr );
	MUTEX_UNLOCK( allocation );

	return( CRYPT_OK );
	}

/* A safe free function that scrubs memory and zeroes the pointer.

	"You will softly and suddenly vanish away
	 And never be met with again"	- Lewis Carroll,
									  "The Hunting of the Snark" */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int krnlMemfree( INOUT_PTR void **pointer )
	{
	MEMLOCK_INFO *memBlockPtr;
	BYTE *memPtr;
	KnRgnDesc rgnDesc = { K_ANYWHERE, 0, 0 };
	int status;

	/* Check the function preconditions */
	status = checkInitFree( pointer, &memPtr, &memBlockPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* Lock the memory list, unlink the new block, and unlock it again */
	MUTEX_LOCK( allocation );
	checkMemCanary( memBlockPtr, memPtr );
	unlinkMemBlock( ( MEMLOCK_INFO ** ) &krnlData->allocatedListHead, 
					( MEMLOCK_INFO ** ) &krnlData->allocatedListTail, 
					memBlockPtr );
	MUTEX_UNLOCK( allocation );

	/* Zeroise the memory (including the memlock info), free it, and zero
	   the pointer */
	rgnDesc.size = memBlockPtr->size;
	rgnDesc.startAddr = memPtr;
	zeroise( memPtr, memBlockPtr->size );
	rgnFree( K_MYACTOR, &rgnDesc );
	*pointer = NULL;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					Macintosh Secure Memory Allocation Functions			*
*																			*
****************************************************************************/

#elif defined( __MAC__ )

#include <Memory.h>

/* A safe malloc function that performs page locking if possible */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int krnlMemalloc( OUT_BUFFER_ALLOC_OPT( size ) void **pointer, 
				  IN_LENGTH int size )
	{
	MEMLOCK_INFO *memBlockPtr;
	BYTE *memPtr;
	int status;

	status = checkInitAlloc( pointer, size );
	if( cryptStatusError( status ) )
		return( status );

	/* Clear return values */
	*pointer = NULL;

	/* Try and allocate the memory */
	adjustMemCanary( size );	/* For canary at end of block */
	if( ( memPtr = clAlloc( "krnlMemAlloc", \
							size + MEMLOCK_HEADERSIZE ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( memPtr, 0, size + MEMLOCK_HEADERSIZE );
	memBlockPtr = ( MEMLOCK_INFO * ) memPtr;
	memBlockPtr->isLocked = FALSE;
	memBlockPtr->size = size + MEMLOCK_HEADERSIZE;
	insertMemCanary( memBlockPtr, memPtr );
	*pointer = memPtr + MEMLOCK_HEADERSIZE;

	/* Try to lock the pages in memory */
#if !defined( CALL_NOT_IN_CARBON ) || CALL_NOT_IN_CARBON
	/* The Mac has two functions for locking memory, HoldMemory() (which
	   makes the memory ineligible for paging) and LockMemory() (which makes
	   it ineligible for paging and also immovable).  We use HoldMemory()
	   since it's slightly more friendly, but really critical applications
	   could use LockMemory() */
	if( HoldMemory( memPtr, memBlockPtr->size ) == noErr )
		memBlockPtr->isLocked = TRUE;
#endif /* Non Mac OS X memory locking */

	/* Lock the memory list, insert the new block, and unlock it again */
	MUTEX_LOCK( allocation );
	insertMemBlock( ( MEMLOCK_INFO ** ) &krnlData->allocatedListHead, 
					( MEMLOCK_INFO ** ) &krnlData->allocatedListTail, 
					memBlockPtr );
	MUTEX_UNLOCK( allocation );

	return( CRYPT_OK );
	}

/* A safe free function that scrubs memory and zeroes the pointer.

	"You will softly and suddenly vanish away
	 And never be met with again"	- Lewis Carroll,
									  "The Hunting of the Snark" */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int krnlMemfree( INOUT_PTR void **pointer )
	{
	MEMLOCK_INFO *memBlockPtr;
	BYTE *memPtr;
	int status;

	/* Check the function preconditions */
	status = checkInitFree( pointer, &memPtr, &memBlockPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* Lock the memory list, unlink the new block, and unlock it again */
	MUTEX_LOCK( allocation );
	checkMemCanary( memBlockPtr, memPtr );
	unlinkMemBlock( ( MEMLOCK_INFO ** ) &krnlData->allocatedListHead, 
					( MEMLOCK_INFO ** ) &krnlData->allocatedListTail, 
					memBlockPtr );
	MUTEX_UNLOCK( allocation );

	/* If the memory is locked, unlock it now */
#if !defined( CALL_NOT_IN_CARBON ) || CALL_NOT_IN_CARBON
	if( memBlockPtr->isLocked )
		UnholdMemory( memPtr, memBlockPtr->size );
#endif /* Non Mac OS X memory locking */

	/* Zeroise the memory (including the memlock info), free it, and zero
	   the pointer */
	zeroise( memPtr, memBlockPtr->size );
	clFree( "krnlMemFree", memPtr );
	*pointer = NULL;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Misc.Secure Memory Allocation Functions				*
*																			*
****************************************************************************/

#else

#if defined( __MSDOS__ ) && defined( __DJGPP__ )
  #include <dpmi.h>
  #include <go32.h>
#endif /* DOS-32 */

/* A safe malloc function that performs page locking if possible */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int krnlMemalloc( OUT_BUFFER_ALLOC_OPT( size ) void **pointer, 
				  IN_LENGTH int size )
	{
	MEMLOCK_INFO *memBlockPtr;
	BYTE *memPtr;
	int status;

	status = checkInitAlloc( pointer, size );
	if( cryptStatusError( status ) )
		return( status );

	/* Clear return values */
	*pointer = NULL;

	/* Try and allocate the memory */
	adjustMemCanary( size );	/* For canary at end of block */
	if( ( memPtr = clAlloc( "krnlMemAlloc", \
							size + MEMLOCK_HEADERSIZE ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( memPtr, 0, size + MEMLOCK_HEADERSIZE );
	memBlockPtr = ( MEMLOCK_INFO * ) memPtr;
	memBlockPtr->isLocked = FALSE;
	memBlockPtr->size = size + MEMLOCK_HEADERSIZE;
	insertMemCanary( memBlockPtr, memPtr );
	*pointer = memPtr + MEMLOCK_HEADERSIZE;

	/* If the OS supports paging, try to lock the pages in memory */
#if defined( __MSDOS__ ) && defined( __DJGPP__ )
	/* Under 32-bit MSDOS use the DPMI functions to lock memory */
	if( _go32_dpmi_lock_data( memPtr, memBlockPtr->size ) == 0)
		memBlockPtr->isLocked = TRUE;
#endif /* Systems that support memory locking */

	/* Lock the memory list, insert the new block, and unlock it again */
	MUTEX_LOCK( allocation );
	insertMemBlock( ( MEMLOCK_INFO ** ) &krnlData->allocatedListHead, 
					( MEMLOCK_INFO ** ) &krnlData->allocatedListTail, 
					memBlockPtr );
	MUTEX_UNLOCK( allocation );

	return( CRYPT_OK );
	}

/* A safe free function that scrubs memory and zeroes the pointer.

	"You will softly and suddenly vanish away
	 And never be met with again"	- Lewis Carroll,
									  "The Hunting of the Snark" */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int krnlMemfree( INOUT_PTR void **pointer )
	{
	MEMLOCK_INFO *memBlockPtr;
	BYTE *memPtr;
	int status;

	/* Check the function preconditions */
	status = checkInitFree( pointer, &memPtr, &memBlockPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* Lock the memory list, unlink the new block, and unlock it again */
	MUTEX_LOCK( allocation );
	checkMemCanary( memBlockPtr, memPtr );
	unlinkMemBlock( ( MEMLOCK_INFO ** ) &krnlData->allocatedListHead, 
					( MEMLOCK_INFO ** ) &krnlData->allocatedListTail, 
					memBlockPtr );
	MUTEX_UNLOCK( allocation );

	/* If the memory is locked, unlock it now */
#if defined( __MSDOS__ ) && defined( __DJGPP__ )
	/* Under 32-bit MSDOS we *could* use the DPMI functions to unlock
	   memory, but as many DPMI hosts implement page locking in a binary
	   form (no lock count maintained), it's better not to unlock anything
	   at all.  Note that this may lead to a shortage of virtual memory in
	   long-running applications */
#endif /* Systems that support memory locking */

	/* Zeroise the memory (including the memlock info), free it, and zero
	   the pointer */
	zeroise( memPtr, memBlockPtr->size );
	clFree( "krnlMemFree", memPtr );
	*pointer = NULL;

	return( CRYPT_OK );
	}
#endif /* OS-specific secure memory handling */
