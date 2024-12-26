# dynamic-memory-allocator

This project implements a custom memory allocator library with advanced debugging, statistics, and memory management features. The allocator supports multiple allocation strategies, block coalescing, and memory defragmentation. It also provides detailed statistics and debugging utilities for tracking memory usage and leaks.

## Features

### Allocation Strategies:
- First Fit
- Best Fit
- Worst Fit
- Next Fit

### Debugging Features:


### Statistics Tracking:
### Advanced Memory Management:

## Build and Usage
### Requirements
- GCC or compatible C compiler
- POSIX-compliant system for mmap and threading support
  
### Compilation

To compile the library, run the following command:
`gcc -pthread -o allocator allocator.c`
Replace `allocator.c` with the name of the file containing the code.
