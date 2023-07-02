#include <stdio.h>
#include <stdlib.h>

typedef void(free_fn)(void *ptr);
typedef void *(malloc_fn)(size_t size);

extern free_fn safe_free;
extern malloc_fn safe_malloc;

void do_test(malloc_fn my_malloc, free_fn my_free, size_t alloc_size,
             size_t write_size) {
  char *alloc = my_malloc(alloc_size);
  printf("Allocated memory at %p\n", alloc);

  for (size_t i = 0; i < write_size; ++i) {
    alloc[i] = 'X';
  }
  my_free(alloc);
}

int main() {
  printf("Enter allocation size: ");
  fflush(stdout);

  size_t alloc_size = 0;
  scanf("%zu", &alloc_size);

  printf("Enter write size: ");
  fflush(stdout);
  size_t write_size = 0;
  scanf("%zu", &write_size);

  printf("System alloc:\n");
  do_test(malloc, free, alloc_size, write_size);
  printf("Done\n");

  printf("Safe alloc:\n");
  do_test(&safe_malloc, &safe_free, alloc_size, write_size);
  printf("Done\n");
  return 0;
}
