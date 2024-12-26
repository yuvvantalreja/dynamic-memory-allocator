# Dynamic Memory Allocator

This project implements a custom memory allocator library with advanced debugging, statistics, and memory management features. The allocator supports multiple allocation strategies, block coalescing, and memory defragmentation. It also provides detailed statistics and debugging utilities for tracking memory usage and leaks.

## Features

### Allocation Strategies:
- First Fit
- Best Fit
- Worst Fit
- Next Fit

### Debugging Features:
- Detection of memory corruption
- Detection of double free
- Memory leak detection

### Statistics Tracking:
- Total memory allocated
- Total memory freed
- Current and peak memory usage
- Total and free block counts
- Fragmentation metrics
- Failed allocation count

### Advanced Memory Management:
- Block splitting and coalescing
- Memory defragmentation
- Alignment support
- Boundary tags for enhanced block validation

## Build and Usage
### Requirements
- GCC or compatible C compiler
- POSIX-compliant system for mmap and threading support
  
### Compilation

To compile the library, run the following command:
`gcc -pthread -o allocator allocator.c`

Replace `allocator.c` with the name of the file containing the code.

### Usage
Include the header file for the allocator in your project:
`#include "allocator.h"`
Use the allocator functions to allocate and free memory:

`void *ptr = my_malloc_debug(size, __FILE__, __LINE__);
my_free_debug(ptr, __FILE__, __LINE__);`

## Design Details

### Block Structure

Each memory block includes a header containing metadata:

- magic: A magic number to detect corruption

- size: Size of the block

- is_free: Block status (free or allocated)

- checksum: Checksum for block validation

- next/prev: Pointers to adjacent blocks

## Allocation Strategies

First Fit: Allocates the first free block that fits the requested size.

Best Fit: Allocates the smallest free block that fits the requested size.

Worst Fit: Allocates the largest free block.

Next Fit: Allocates the next suitable block, starting from the last allocation.

## Thread Safety

The allocator is thread-safe, using pthread_mutex to synchronize access to the heap.

## Memory Growth

The heap grows dynamically using mmap. The growth factor is controlled by `HEAP_GROWTH_FACTOR` and `MIN_HEAP_GROWTH`.

## Contribution

Contributions are welcome! Please submit a pull request or report issues via the GitHub repository.

## Authors

Developed by Yuvvan Talreja
