#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/mman.h>

#define MIN_BLOCK_SIZE 32
#define ALIGNMENT 16
#define HEAP_GROWTH_FACTOR 2
#define MIN_HEAP_GROWTH 4096
#define MAX_HEAP_SIZE (1ULL << 32)
#define MAGIC_NUMBER 0xDEADBEEF

typedef enum
{
    ALLOC_FIRST_FIT,
    ALLOC_BEST_FIT,
    ALLOC_WORST_FIT,
    ALLOC_NEXT_FIT
} allocation_strategy_t;

typedef enum
{
    ALLOC_OK = 0,
    ALLOC_ERROR_OUT_OF_MEMORY,
    ALLOC_ERROR_INVALID_PARAMETER,
    ALLOC_ERROR_CORRUPTION,
    ALLOC_ERROR_DOUBLE_FREE,
    ALLOC_ERROR_UNALIGNED_REQUEST
} allocator_error_t;

typedef struct block_header
{
    uint32_t magic;
    size_t size;
    int is_free;
    struct block_header *next;
    struct block_header *prev;
    const char *alloc_file;
    int alloc_line;
    pthread_t owner_thread;
    uint32_t checksum;
} block_header_t;

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

static block_header_t *heap_start = NULL;
static block_header_t *last_allocated_block = NULL;
static pthread_mutex_t heap_mutex = PTHREAD_MUTEX_INITIALIZER;
static allocation_strategy_t current_strategy = ALLOC_FIRST_FIT;
static allocator_stats_t stats = {0};
static allocator_error_t last_error = ALLOC_OK;

static uint32_t calculate_checksum(block_header_t *block);
static bool validate_block(block_header_t *block);
static void update_stats_alloc(size_t size);
static void update_stats_free(size_t size);
static void *handle_allocation_error(const char *msg);

static uint32_t calculate_checksum(block_header_t *block)
{
    uint32_t sum = 0;
    uint8_t *ptr = (uint8_t *)block;

    for (size_t i = 0; i < offsetof(block_header_t, checksum); i++)
    {
        sum = (sum << 1) | (sum >> 31);
        sum ^= ptr[i];
    }
    return sum;
}

static bool validate_block(block_header_t *block)
{
    if (!block)
        return false;

    if (block->magic != MAGIC_NUMBER)
    {
        last_error = ALLOC_ERROR_CORRUPTION;
        return false;
    }

    uint32_t calculated_checksum = calculate_checksum(block);
    if (calculated_checksum != block->checksum)
    {
        last_error = ALLOC_ERROR_CORRUPTION;
        return false;
    }

    if (block->size < MIN_BLOCK_SIZE ||
        block->size > MAX_HEAP_SIZE ||
        (block->size & (ALIGNMENT - 1)))
    {
        last_error = ALLOC_ERROR_CORRUPTION;
        return false;
    }

    return true;
}

static block_header_t *find_first_fit(size_t size)
{
    block_header_t *current = heap_start;
    while (current)
    {
        if (current->is_free && current->size >= size)
        {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

static block_header_t *find_best_fit(size_t size)
{
    block_header_t *best = NULL;
    size_t min_diff = SIZE_MAX;
    block_header_t *current = heap_start;

    while (current)
    {
        if (current->is_free && current->size >= size)
        {
            size_t diff = current->size - size;
            if (diff < min_diff)
            {
                min_diff = diff;
                best = current;
            }
        }
        current = current->next;
    }
    return best;
}

static block_header_t *find_worst_fit(size_t size)
{
    block_header_t *worst = NULL;
    size_t max_diff = 0;
    block_header_t *current = heap_start;

    while (current)
    {
        if (current->is_free && current->size >= size)
        {
            size_t diff = current->size - size;
            if (diff > max_diff)
            {
                max_diff = diff;
                worst = current;
            }
        }
        current = current->next;
    }
    return worst;
}

static block_header_t *find_next_fit(size_t size)
{
    if (!last_allocated_block)
    {
        return find_first_fit(size);
    }

    block_header_t *current = last_allocated_block->next;
    while (current != last_allocated_block)
    {
        if (!current)
        {
            current = heap_start;
        }
        if (current->is_free && current->size >= size)
        {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

static void *request_space(size_t minimum_size)
{
    size_t growth_size = minimum_size;

    if (growth_size < MIN_HEAP_GROWTH)
    {
        growth_size = MIN_HEAP_GROWTH;
    }
    else
    {
        growth_size *= HEAP_GROWTH_FACTOR;
    }

    if (growth_size > MAX_HEAP_SIZE ||
        stats.current_usage + growth_size > MAX_HEAP_SIZE)
    {
        last_error = ALLOC_ERROR_OUT_OF_MEMORY;
        return NULL;
    }

    void *space = mmap(NULL, growth_size,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       -1, 0);

    if (space == MAP_FAILED)
    {
        last_error = ALLOC_ERROR_OUT_OF_MEMORY;
        return NULL;
    }

    return space;
}

static void split_block(block_header_t *block, size_t size)
{
    if (block->size >= size + MIN_BLOCK_SIZE)
    {
        block_header_t *new_block = (block_header_t *)((char *)block + size);

        new_block->magic = MAGIC_NUMBER;
        new_block->size = block->size - size;
        new_block->is_free = 1;
        new_block->next = block->next;
        new_block->prev = block;
        new_block->alloc_file = NULL;
        new_block->alloc_line = 0;
        new_block->owner_thread = 0;
        new_block->checksum = calculate_checksum(new_block);

        if (block->next)
        {
            block->next->prev = new_block;
        }

        block->next = new_block;
        block->size = size;
        block->checksum = calculate_checksum(block);

        stats.total_blocks++;
        stats.free_blocks++;
    }
}

static void update_stats_alloc(size_t size)
{
    stats.total_allocated += size;
    stats.current_usage += size;
    stats.peak_usage = (stats.current_usage > stats.peak_usage) ? stats.current_usage : stats.peak_usage;
    stats.total_operations++;
    stats.free_blocks--;
}

static void update_stats_free(size_t size)
{
    stats.total_freed += size;
    stats.current_usage -= size;
    stats.total_operations++;
    stats.free_blocks++;
}

void *my_malloc_debug(size_t size, const char *file, int line)
{
    pthread_mutex_lock(&heap_mutex);

    if (size == 0)
    {
        pthread_mutex_unlock(&heap_mutex);
        return NULL;
    }

    size_t total_size = (size + sizeof(block_header_t) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1);
    if (total_size < MIN_BLOCK_SIZE)
    {
        total_size = MIN_BLOCK_SIZE;
    }

    block_header_t *block = NULL;

    switch (current_strategy)
    {
    case ALLOC_FIRST_FIT:
        block = find_first_fit(total_size);
        break;
    case ALLOC_BEST_FIT:
        block = find_best_fit(total_size);
        break;
    case ALLOC_WORST_FIT:
        block = find_worst_fit(total_size);
        break;
    case ALLOC_NEXT_FIT:
        block = find_next_fit(total_size);
        break;
    }

    if (!block)
    {
        block = request_space(total_size);
        if (!block)
        {
            stats.failed_allocations++;
            pthread_mutex_unlock(&heap_mutex);
            return NULL;
        }

        block->magic = MAGIC_NUMBER;
        block->size = total_size;
        block->is_free = 0;
        block->next = NULL;
        block->prev = NULL;
        block->alloc_file = file;
        block->alloc_line = line;
        block->owner_thread = pthread_self();
        block->checksum = calculate_checksum(block);

        if (!heap_start)
        {
            heap_start = block;
        }
        else
        {
            block_header_t *current = heap_start;
            while (current->next)
            {
                current = current->next;
            }
            current->next = block;
            block->prev = current;
        }

        stats.total_blocks++;
    }
    else
    {
        block->is_free = 0;
        block->alloc_file = file;
        block->alloc_line = line;
        block->owner_thread = pthread_self();
        split_block(block, total_size);
    }

    last_allocated_block = block;
    update_stats_alloc(block->size);

    pthread_mutex_unlock(&heap_mutex);
    return (void *)((char *)block + sizeof(block_header_t));
}

static void coalesce(block_header_t *block)
{
    if (!validate_block(block))
        return;

    if (block->next && validate_block(block->next) && block->next->is_free)
    {
        block->size += block->next->size;
        block->next = block->next->next;
        if (block->next)
        {
            block->next->prev = block;
        }
        stats.total_blocks--;
        stats.free_blocks--;
        block->checksum = calculate_checksum(block);
    }

    if (block->prev && validate_block(block->prev) && block->prev->is_free)
    {
        block->prev->size += block->size;
        block->prev->next = block->next;
        if (block->next)
        {
            block->next->prev = block->prev;
        }
        stats.total_blocks--;
        stats.free_blocks--;
        block->prev->checksum = calculate_checksum(block->prev);
        block = block->prev;
    }
}

void my_free_debug(void *ptr, const char *file, int line)
{
    if (!ptr)
        return;

    pthread_mutex_lock(&heap_mutex);

    block_header_t *block = (block_header_t *)((char *)ptr - sizeof(block_header_t));

    if (!validate_block(block))
    {
        fprintf(stderr, "Memory corruption detected at %s:%d\n", file, line);
        pthread_mutex_unlock(&heap_mutex);
        return;
    }

    if (block->is_free)
    {
        fprintf(stderr, "Double free detected at %s:%d\n", file, line);
        last_error = ALLOC_ERROR_DOUBLE_FREE;
        pthread_mutex_unlock(&heap_mutex);
        return;
    }

    if (block->prev)
    {
        block->prev->next = block->next;
    }
    else
    {
        heap_start = block->next;
    }
    if (block->next)
    {
        block->next->prev = block->prev;
    }

    if (munmap(block, block->size) == -1)
    {
        fprintf(stderr, "Error unmapping memory at %s:%d\n", file, line);
    }

    update_stats_free(block->size);

    pthread_mutex_unlock(&heap_mutex);
}

void set_allocation_strategy(allocation_strategy_t strategy)
{
    pthread_mutex_lock(&heap_mutex);
    current_strategy = strategy;
    pthread_mutex_unlock(&heap_mutex);
}

allocator_stats_t get_allocator_stats()
{
    pthread_mutex_lock(&heap_mutex);
    allocator_stats_t current_stats = stats;
    pthread_mutex_unlock(&heap_mutex);
    return current_stats;
}

allocator_error_t get_last_error()
{
    return last_error;
}

void print_heap_debug()
{
    pthread_mutex_lock(&heap_mutex);

    block_header_t *current = heap_start;
    printf("\n=== Heap State ===\n");
    while (current)
    {
        if (!validate_block(current))
        {
            printf("CORRUPTED BLOCK DETECTED at %p\n", (void *)current);
            break;
        }

        printf("Block at %p:\n", (void *)current);
        printf("  Size: %zu bytes\n", current->size);
        printf("  Status: %s\n", current->is_free ? "FREE" : "ALLOCATED");
        if (!current->is_free)
        {
            printf("  Allocated at: %s:%d\n", current->alloc_file, current->alloc_line);
            printf("  Owner thread: %lu\n", (unsigned long)current->owner_thread);
        }
        printf("  Next: %p\n", (void *)current->next);
        printf("  Prev: %p\n", (void *)current->prev);
        printf("  Checksum: 0x%08x\n\n", current->checksum);

        current = current->next;
    }

    // Print statistics
    printf("\n=== Allocator Statistics ===\n");
    printf("Total allocated: %zu bytes\n", stats.total_allocated);
    printf("Total freed: %zu bytes\n", stats.total_freed);
    printf("Current usage: %zu bytes\n", stats.current_usage);
    printf("Peak usage: %zu bytes\n", stats.peak_usage);
    printf("Total blocks: %zu\n", stats.total_blocks);
    printf("Free blocks: %zu\n", stats.free_blocks);
    printf("Fragmentation count: %zu\n", stats.fragmentation_count);
    printf("Failed allocations: %zu\n", stats.failed_allocations);
    printf("Total operations: %zu\n\n", stats.total_operations);

    pthread_mutex_unlock(&heap_mutex);
}

// Memory defragmentation function
void defragment_heap()
{
    pthread_mutex_lock(&heap_mutex);

    bool changed;
    size_t initial_fragments = stats.fragmentation_count;

    do
    {
        changed = false;
        block_header_t *current = heap_start;

        while (current && current->next)
        {
            if (current->is_free && current->next->is_free)
            {
                coalesce(current);
                changed = true;
            }
            current = current->next;
        }
    } while (changed);

    stats.fragmentation_count = initial_fragments -
                                (initial_fragments - stats.free_blocks + 1);

    pthread_mutex_unlock(&heap_mutex);
}

typedef struct
{
    const char *file;
    int line;
    size_t size;
    pthread_t thread;
    void *ptr;
} leak_info_t;

#define MAX_LEAKS 1000
static leak_info_t leaked_blocks[MAX_LEAKS];
static size_t leak_count = 0;

void check_leaks()
{
    pthread_mutex_lock(&heap_mutex);

    leak_count = 0;
    block_header_t *current = heap_start;

    while (current && leak_count < MAX_LEAKS)
    {
        if (!current->is_free)
        {
            leaked_blocks[leak_count].file = current->alloc_file;
            leaked_blocks[leak_count].line = current->alloc_line;
            leaked_blocks[leak_count].size = current->size;
            leaked_blocks[leak_count].thread = current->owner_thread;
            leaked_blocks[leak_count].ptr = (void *)((char *)current + sizeof(block_header_t));
            leak_count++;
        }
        current = current->next;
    }

    if (leak_count > 0)
    {
        printf("\n=== Memory Leaks Detected ===\n");
        for (size_t i = 0; i < leak_count; i++)
        {
            printf("Leak #%zu:\n", i + 1);
            printf("  Location: %s:%d\n", leaked_blocks[i].file, leaked_blocks[i].line);
            printf("  Size: %zu bytes\n", leaked_blocks[i].size);
            printf("  Thread: %lu\n", (unsigned long)leaked_blocks[i].thread);
            printf("  Address: %p\n\n", leaked_blocks[i].ptr);
        }
        printf("Total leaks: %zu\n\n", leak_count);
    }

    pthread_mutex_unlock(&heap_mutex);
}

typedef struct boundary_tag
{
    size_t size;
    int is_free;
} boundary_tag_t;

static void add_boundary_tags(block_header_t *block)
{
    boundary_tag_t *footer = (boundary_tag_t *)((char *)block + block->size - sizeof(boundary_tag_t));
    footer->size = block->size;
    footer->is_free = block->is_free;
}

static boundary_tag_t *get_previous_footer(block_header_t *block)
{
    return (boundary_tag_t *)((char *)block - sizeof(boundary_tag_t));
}

#define POOL_BLOCK_SIZE 64
#define POOL_BLOCKS_PER_CHUNK 64

typedef struct pool_chunk
{
    char blocks[POOL_BLOCKS_PER_CHUNK][POOL_BLOCK_SIZE];
    uint64_t used_blocks;
    struct pool_chunk *next;
} pool_chunk_t;

static pool_chunk_t *small_pools = NULL;
static pthread_mutex_t pool_mutex = PTHREAD_MUTEX_INITIALIZER;

void *allocate_from_pool()
{
    pthread_mutex_lock(&pool_mutex);

    pool_chunk_t *chunk = small_pools;
    while (chunk)
    {
        if (chunk->used_blocks != UINT64_MAX)
        {
            // Find first free block
            for (int i = 0; i < POOL_BLOCKS_PER_CHUNK; i++)
            {
                if (!(chunk->used_blocks & (1ULL << i)))
                {
                    chunk->used_blocks |= (1ULL << i);
                    pthread_mutex_unlock(&pool_mutex);
                    return &chunk->blocks[i];
                }
            }
        }
        chunk = chunk->next;
    }

    chunk = my_malloc_debug(sizeof(pool_chunk_t), __FILE__, __LINE__);
    if (!chunk)
    {
        pthread_mutex_unlock(&pool_mutex);
        return NULL;
    }

    chunk->used_blocks = 1;
    chunk->next = small_pools;
    small_pools = chunk;

    pthread_mutex_unlock(&pool_mutex);
    return &chunk->blocks[0];
}

bool validate_heap()
{
    pthread_mutex_lock(&heap_mutex);
    bool valid = true;
    block_header_t *current = heap_start;
    size_t counted_blocks = 0;
    size_t counted_free_blocks = 0;

    while (current && valid)
    {
        if (!validate_block(current))
        {
            valid = false;
            break;
        }

        if ((size_t)current & (ALIGNMENT - 1))
        {
            valid = false;
            break;
        }

        if (current->size < MIN_BLOCK_SIZE || current->size > MAX_HEAP_SIZE)
        {
            valid = false;
            break;
        }

        if (current->next)
        {
            if (current->next->prev != current)
            {
                valid = false;
                break;
            }
        }

        counted_blocks++;
        if (current->is_free)
        {
            counted_free_blocks++;
        }

        current = current->next;
    }

    if (counted_blocks != stats.total_blocks ||
        counted_free_blocks != stats.free_blocks)
    {
        valid = false;
    }

    pthread_mutex_unlock(&heap_mutex);
    return valid;
}

#define my_malloc(size) my_malloc_debug(size, __FILE__, __LINE__)
#define my_free(ptr) my_free_debug(ptr, __FILE__, __LINE__)