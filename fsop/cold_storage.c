#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ALLOC_SIZE 256

/*
 * Cold storage
 *
 * User can create temporary buckets and write data
 * to them, but cannot read data
 *
 * Two types of storage buckets
 *   - in memory (malloc)
 *   - on disk (file*)
 *
 * Index bug to allow reading data into a file* struct
 * Overwrite FILE* structure with user defined data
 * Leak admin password (flag)
 */

char admin_password[0x100] = {0};

void __attribute__((constructor)) setup() {
  assert(setvbuf(stdout, NULL, _IONBF, 0) == 0);
  assert(setvbuf(stdin, NULL, _IONBF, 0) == 0);

  FILE *fp = fopen("./flag.txt", "r");

  assert(fp != NULL && "Failed to open admin password file");

  unsigned long nchrs =
      fread(admin_password, 1, sizeof(admin_password) - 1, fp);
  assert(nchrs > 0 && "Failed to read admin password");

  admin_password[nchrs] = 0;

  fclose(fp);
}

void __attribute__((destructor)) cleanup() {}

/*
 * First 8 buckets are file buckets, other 8 are memory buckets
 */

#define ARRAY_SIZE(X) (sizeof(X) / sizeof(X[0]))

size_t file_buckets = 0;
size_t mem_buckets = 0;

typedef struct bucket {
  void *mem;
  size_t size;
} bucket_t;

bucket_t buckets[16] = {0};

#define FILE_BUCKETS_FIRST 0
#define FILE_BUCKETS_LAST 8

#define MEM_BUCKETS_FIRST 8
#define MEM_BUCKETS_LAST ARRAY_SIZE(buckets)

void create_file_bucket(size_t index) {
  if (buckets[index].mem == NULL && buckets[index].size == 0) {
    buckets[index].mem = tmpfile();
    buckets[index].size = sizeof(FILE);
    printf("Success!\n");
  } else {
    printf("Failed!\n");
  }
}

void write_file_bucket(size_t index) {
  char buf[ALLOC_SIZE] = {0};

  if (buckets[index].mem != NULL && buckets[index].size != 0) {
    size_t nbytes = fread(buf, sizeof(buf[0]), ARRAY_SIZE(buf), stdin);
    printf("Data: ");
    assert(fwrite(buf, sizeof(buf[0]), nbytes, buckets[index].mem) > 0 &&
           "Failed to write into file bucket\n");
    printf("Success!\n");
  } else {
    printf("Failed!\n");
  }
}

void create_mem_bucket(size_t index) {
  if (buckets[index].mem == NULL && buckets[index].size == 0) {
    buckets[index].mem = calloc(1, ALLOC_SIZE);
    assert(buckets[index].mem != NULL && "Failed to allocate bucket");
    buckets[index].size = ALLOC_SIZE;
    printf("Success!\n");
  } else {
    printf("Failed!\n");
  }
}

void write_mem_bucket(size_t index) {
  char buf[ALLOC_SIZE] = {0};

  if (buckets[index].mem != NULL && buckets[index].size != 0) {
    printf("Data: ");
    size_t nbytes = fread(buf, 1, buckets[index].size, stdin);
    memcpy(buckets[index].mem, buf, nbytes);
    printf("Success!\n");
  } else {
    printf("Failed!\n");
  }
}

void read_mem_bucket(size_t index) {
  if (buckets[index].mem != NULL && buckets[index].size != 0) {
    printf("Data: ");
    for (size_t i = 0; i < buckets[index].size; i++) {
      printf("%02hhx", ((char *)buckets[index].mem)[i]);
    }
    printf("\n");
  } else {
    printf("Failed!\n");
  }
}

void banner() { puts("Welcome to the ColdStorage management interface."); }

#define CREATE_MEMORY 1
#define WRITE_MEMORY 2
#define READ_MEMORY 3
#define CREATE_FILE 4
#define WRITE_FILE 5

void menu() {
  printf("1. Create memory backed bucket\n");
  printf("2. Write memory backed bucket\n");
  printf("3. Read memory backed bucket\n");
  printf("4. Create file backed bucket\n");
  printf("5. Write file backed bucket\n");
  printf("> ");
}

size_t read_choice() {
  size_t choice;
  if (scanf("%zu", &choice) != 1) {
    printf("Invalid choice\n");
    exit(1);
  }
  getchar();
  return choice;
}

size_t read_index() {
  size_t index;
  printf("Index: ");
  if (scanf("%zu", &index) != 1) {
    printf("Invalid choice\n");
    exit(2);
  }
  getchar();
  return index;
}

int main() {
  banner();

  while (1) {
    menu();
    size_t choice = read_choice();

    switch (choice) {
    case WRITE_FILE:
    case CREATE_FILE: {
      size_t index = read_index();

      if (index >= FILE_BUCKETS_LAST) {
        index = index % FILE_BUCKETS_LAST;
      }

      if (choice == WRITE_FILE) {
        write_file_bucket(index);
      } else if (choice == CREATE_FILE) {
        create_file_bucket(index);
      }
    } break;
    case READ_MEMORY:
    case WRITE_MEMORY:
    case CREATE_MEMORY: {
      size_t index = read_index();

      if (index < MEM_BUCKETS_FIRST) {
        index = MEM_BUCKETS_FIRST;
      }

      if (index >= MEM_BUCKETS_LAST) {
        index = index % MEM_BUCKETS_LAST;
      }

      if (choice == WRITE_MEMORY) {
        write_mem_bucket(index);
      } else if (choice == CREATE_MEMORY) {
        create_mem_bucket(index);
      } else if (choice == READ_MEMORY) {
        read_mem_bucket(index);
      }
    } break;
    default: {
      printf("Invalid choice\n");
      exit(1);
    }
    }
  }
  printf("Password was: %s\n", admin_password);
}
