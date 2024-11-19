#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

void argument_stack(char **argv, int argc, struct intr_frame *if_);

/** #Project 2: System Call */
thread_t *get_child_process(int pid);
int process_add_file(struct file *f);
struct file *process_get_file(int fd);
int process_close_file(int fd);
process_insert_file(int fd, struct file *f);


#define STDIN 1
#define STDOUT 2
#define STDERR 3

/** #Project 2: Extend File Descriptor - 공유 자원 검증용 구조체 */
#define DICTLEN 100

struct dict_elem{
	uintptr_t key;
	uintptr_t value;
};


#endif /* userprog/process.h */
