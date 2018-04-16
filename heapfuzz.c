#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ucontext.h>
/*
 * Author: Daniele Linguaglossa
 *
 * Please compile with gcc -shared -fPIC -o heapfuzz.so heapfuzz.c -ldl
 * then use LD_PRELOAD=./heapfuzz.so and USE_HEAPFUZZ=1 to run your binary
*/

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

enum Overflow {
	HEAP_WRITE_OOB=1,
	HEAP_READ_OOB=2,
    FREE_NON_ALLOC=3,
    DOUBLE_FREE=4,
	USE_AFTER_FREE=5,
	SEGMENTATION_FAULT = 6,
};

struct allocated_area {
	void * ptr;
	size_t size;
        void * endaddr;
	void * rw_page;
	void * none_page;
	int free;
};

char * IPC_NAME = "/tmp/heapfuzz";
int IPC_FD = -1;
int idx = 0;
int area_size = 0;
struct allocated_area areas[1024];

static char* (*real_strcpy)(char * dst, const char * src)=NULL;
static void (*real_free)(void *ptr)=NULL;
static void* (*real_malloc)(size_t)=NULL;
static void* (*real_calloc)(size_t nitems, size_t size)=NULL;
static void* (*real_realloc)(void *ptr, size_t size)=NULL;
static int (*real__libc_start_main)(int (*main) (int,char **,char **),int argc,char **ubp_av,void (*init) (void),void (*fini)(void),void (*rtld_fini)(void),void (*stack_end)) = NULL;
static ssize_t (*real_read)(int, void*, size_t)=NULL;

static void mtrace_init(void)
{
    int err = 0;
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_free = dlsym(RTLD_NEXT, "free");
    real_strcpy = dlsym(RTLD_NEXT, "strcpy");
    real_calloc = dlsym(RTLD_NEXT, "calloc");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    real_strcpy = dlsym(RTLD_NEXT, "strcpy");
    real_read = dlsym(RTLD_NEXT, "read");
    real__libc_start_main = dlsym(RTLD_NEXT,"__libc_start_main");

    if (NULL == real_malloc) {
        fprintf(stderr, "Error in `dlsym(malloc)`: %s\n", dlerror());
	err = 1;
    }else if(NULL == real_free) {
        fprintf(stderr, "Error in `dlsym(free)`: %s\n", dlerror());
	err = 1;
    }else if(NULL == real_strcpy) {
        fprintf(stderr, "Error in `dlsym(strcpy)`: %s\n", dlerror());
	err = 1;
    }else if(NULL == real_calloc) {
        fprintf(stderr, "Error in `dlsym(calloc)`: %s\n", dlerror());
	err = 1;
    }else if(NULL == real_realloc) {
        fprintf(stderr, "Error in `dlsym(realloc)`: %s\n", dlerror());
	err = 1;
    }else if(NULL == real_strcpy) {
        fprintf(stderr, "Error in `dlsym(strcpy)`: %s\n", dlerror());
	err = 1;
    }else if(NULL == real__libc_start_main) {
        fprintf(stderr, "Error in `dlsym(__libc_start_main)`: %s\n", dlerror());
	err = 1;
    }

    if( err ){
       exit(-1);
    }
}

static void handler(int sig, siginfo_t *si, void *context)
{
    ucontext_t *u = (ucontext_t *)context;
    for(int i=0; i<area_size; i++)
    {
        if(si->si_addr < areas[i].none_page && si->si_addr >= areas[i].rw_page)
        {
           if(areas[i].free)
           {
	        display_vuln(USE_AFTER_FREE,  si->si_addr,  0, 0);
           }

           if(u->uc_mcontext.gregs[REG_ERR] & 0x2){
              display_vuln(HEAP_WRITE_OOB,  si->si_addr,  0, 0);
           }else{
               display_vuln(HEAP_READ_OOB,  si->si_addr,  0, 0);
           }
        }
    }

     if(u->uc_mcontext.gregs[REG_ERR] & 0x2){
         display_vuln(SEGMENTATION_FAULT,  si->si_addr,  0, 0);
     }else{
         display_vuln(SEGMENTATION_FAULT,  si->si_addr,  0, 0);
     }
}


int get_area_index(void *ptr)
{
   for(int i=0; i<area_size; i++)
   {
       if(areas[i].ptr == ptr)
       {
           return i;
       }
   }
   return -1;
}


ssize_t read(int fildes, void *buf, size_t nbyte)
{
   if(real_read==NULL) {
        mtrace_init();
   }
   int index = get_area_index(buf);
   if(index >= 0)
   {
      if(areas[index].size < nbyte)
      {
	 display_vuln(HEAP_WRITE_OOB, buf, areas[index].size, nbyte);
      }else{
          ssize_t s = real_read(fildes, buf, nbyte);
          return s;
      }
   }else{
      ssize_t s = real_read(fildes, buf, nbyte);
      return s;
   }
}

void * map(size_t s , int prot){
    void *ptr = mmap(0, s, prot, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (map == MAP_FAILED) {
	perror("Error mmapping the file");
	exit(-1);
    }
    return ptr;
}

void * add_area(int * index, size_t size)
{

    areas[*index].none_page = map(size, PROT_NONE);
    areas[*index].rw_page = map(size, PROT_READ|PROT_WRITE);
    areas[*index].ptr = areas[*index].none_page - size;
    areas[*index].size = size;
    areas[*index].free = 0;
    area_size++;
    return areas[*index].ptr;
}

void free_area(int index)
{
    areas[index].free = 1;
    if(mprotect(areas[index].rw_page,0x1000, PROT_NONE) != 0)
    {
       perror("mprotect error!");
    }
}


void display_vuln(enum Overflow kind, void * ptr, size_t org_size, size_t new_size)
{
   char * estr;
   if(kind == HEAP_WRITE_OOB){
      estr="HEAP WRITE OOB";
   }else if(kind == HEAP_READ_OOB){
      estr="HEAP READ OOB";
   }else if(kind == FREE_NON_ALLOC){
      estr="FREE NON ALLOC";
   }else if(kind == DOUBLE_FREE){
      estr="DOUBLE FREE";
   }else if(kind == USE_AFTER_FREE){
      estr="USE AFTER FREE";
   }else if(kind == SEGMENTATION_FAULT){
      estr="SEGMENTATION FAULT";
   }

   char * heapfuzz = getenv("USE_HEAPFUZZ");

   if(heapfuzz != NULL && strcmp(heapfuzz, "1")==0){
      char cmd[128];
      memset(cmd, 0, sizeof(cmd));
      sprintf(cmd,"%d-%p-%d-%d",kind,ptr,org_size, new_size);
      int len = strlen(cmd);
      write(IPC_FD,(char *)&len, sizeof(len));
      write(IPC_FD, cmd, strlen(cmd));
   }else{
     fprintf(stderr, "\n" "=================================================================\n" ANSI_COLOR_CYAN "%s" ANSI_COLOR_RESET
	  " (ptr=" ANSI_COLOR_GREEN "%p" ANSI_COLOR_RESET " buffer_size=" ANSI_COLOR_GREEN "0x%x" ANSI_COLOR_RESET " write_size=" ANSI_COLOR_GREEN "0x%x" 	   ANSI_COLOR_RESET ")\n" "=================================================================" "\n" ANSI_COLOR_RESET, estr, ptr, org_size,  new_size
       );
   }
   exit(-1);
}

int __libc_start_main(int (*main) (int,char **,char **),int argc,char **ubp_av,void (*init) (void),void (*fini)(void),void (*rtld_fini)(void),
void (*stack_end)) {

    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_flags = SA_SIGINFO;
    action.sa_sigaction = handler;
    sigaction(SIGSEGV, &action, NULL);

    if(real__libc_start_main==NULL) {
        mtrace_init();
    }
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    char * heapfuzz = getenv("USE_HEAPFUZZ");
    if(heapfuzz != NULL && strcmp(heapfuzz, "1")==0){
       char init_message[4];
       mkfifo(IPC_NAME, 0777);
       IPC_FD = open(IPC_NAME, O_RDWR);
       return real__libc_start_main(main,argc,ubp_av,init,fini,rtld_fini,stack_end);
    }else{
       return real__libc_start_main(main,argc,ubp_av,init,fini,rtld_fini,stack_end);
    }
}


char* strcpy(char * dst, const char * src)
{
    if(real_strcpy==NULL) {
        mtrace_init();
    }

    char * d = real_strcpy(dst, src);
    return d;
}

void free(void *ptr)
{
   if(real_free==NULL) {
        mtrace_init();
    }

   int index = get_area_index(ptr);
   if(index >=0)
   {
      if(areas[index].free == 1)
      {
          display_vuln(DOUBLE_FREE, ptr,0, 0);
      }else{
         free_area(index);
      }
   }else{
       display_vuln(FREE_NON_ALLOC, ptr, 0, 0);
   }

}

void *malloc(size_t size)
{
    if(real_malloc==NULL) {
        mtrace_init();
    }
    void *p = add_area(&idx, size);
    return p;
}

void *calloc(size_t nitems, size_t size)
{
    if(real_calloc==NULL) {
        mtrace_init();
    }

    int filled = 0;
    void *p = add_arena(&idx, nitems*size);
    return p;
}

void * realloc(void *ptr, size_t size)
{
    if(real_realloc==NULL) {
        mtrace_init();
    }

    for(int i=0; i<area_size; i++){
      if(areas[i].ptr == ptr){
         areas[i].size = size;
         areas[i].ptr = areas[i].none_page - size;
        return areas[i].ptr;
      }
    }

    return real_realloc(ptr, size);
}

char *strdup (const char *s)
{
    char *d = malloc (strlen (s) + 1);
    if (d == NULL) return NULL;
    strcpy (d,s);
    return d;
}

