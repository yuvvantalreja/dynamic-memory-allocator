#include <stdio.h>
#include <string.h>
#include "allocator.h"

void test_basic_allocation()
{
    printf("\nTesting basic allocation...\n");

    int *numbers = (int *)my_malloc(5 * sizeof(int));
    if (numbers)
    {
        printf("Successfully allocated array of 5 integers\n");
        for (int i = 0; i < 5; i++)
        {
            numbers[i] = i + 1;
        }
        printf("Written values: ");
        for (int i = 0; i < 5; i++)
        {
            printf("%d ", numbers[i]);
        }
        printf("\n");
        my_free(numbers);
        printf("Successfully freed array\n");
    }

    char *str1 = (char *)my_malloc(20);
    char *str2 = (char *)my_malloc(20);
    if (str1 && str2)
    {
        strcpy(str1, "Hello");
        strcpy(str2, "World");
        printf("str1: %s, str2: %s\n", str1, str2);
        my_free(str1);
        my_free(str2);
    }
}

void test_different_sizes()
{
    printf("\nTesting different allocation sizes...\n");

    void *p1 = my_malloc(10);
    void *p2 = my_malloc(1000);
    void *p3 = my_malloc(100000);

    printf("Allocated sizes: 10, 1000, 100000 bytes\n");
    print_heap_debug();

    my_free(p1);
    my_free(p2);
    my_free(p3);
}

void test_fragmentation()
{
    printf("\nTesting fragmentation...\n");

    void *blocks[10];

    // Allocate 10 blocks
    for (int i = 0; i < 10; i++)
    {
        blocks[i] = my_malloc(100);
    }

    for (int i = 0; i < 10; i += 2)
    {
        my_free(blocks[i]);
    }

    print_heap_debug();
    printf("\nDefragmenting heap...\n");
    defragment_heap();
    print_heap_debug();
}

void test_allocation_strategies()
{
    printf("\nTesting different allocation strategies...\n");

    set_allocation_strategy(ALLOC_FIRST_FIT);
    void *p1 = my_malloc(100);
    printf("\nFirst Fit allocation:\n");
    print_heap_debug();
    my_free(p1);

    set_allocation_strategy(ALLOC_BEST_FIT);
    void *p2 = my_malloc(200);
    printf("\nBest Fit allocation:\n");
    print_heap_debug();
    my_free(p2);

    set_allocation_strategy(ALLOC_WORST_FIT);
    void *p3 = my_malloc(300);
    printf("\nWorst Fit allocation:\n");
    print_heap_debug();
    my_free(p3);
}

void test_memory_leaks()
{
    printf("\nTesting memory leak detection...\n");

    my_malloc(100);
    my_malloc(200);

    check_leaks();
}

int main()
{
    printf("Starting memory allocator tests...\n");

    test_basic_allocation();
    test_different_sizes();
    test_fragmentation();
    test_allocation_strategies();
    test_memory_leaks();

    printf("\nAll tests completed.\n");
    return 0;
}