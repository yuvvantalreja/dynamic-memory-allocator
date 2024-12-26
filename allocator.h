#ifndef ALLOCATOR_H
#define ALLOCATOR_H

#include <stddef.h>

typedef enum
{
    ALLOC_FIRST_FIT,
    ALLOC_BEST_FIT,
    ALLOC_WORST_FIT,
    ALLOC_NEXT_FIT
} allocation_strategy_t;

typedef struct
{
    size_t total_allocated;
    size_t total_freed;
    size_t current_usage;
    size_t peak_usage;
    size_t total_blocks;
    size_t free_blocks;
    size_t fragmentation_count;
    size_t failed_allocations;
    size_t total_operations;
} allocator_stats_t;

void *my_malloc_debug(size_t size, const char *file, int line);
void my_free_debug(void *ptr, const char *file, int line);

void set_allocation_strategy(allocation_strategy_t strategy);
allocator_stats_t get_allocator_stats(void);
void print_heap_debug(void);
void defragment_heap(void);
void check_leaks(void);

#define my_malloc(size) my_malloc_debug(size, __FILE__, __LINE__)
#define my_free(ptr) my_free_debug(ptr, __FILE__, __LINE__)

#endif