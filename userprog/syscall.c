#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"


/** #Project 2: System Call */
#include <string.h>

#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "userprog/process.h"
/** -----------------------  */

/** #Project 2: System Call */
struct lock filesys_lock;  // 파일 읽기/쓰기 용 lock

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

    /** #Project 2: System Call - read & write 용 lock 초기화 */
    lock_init(&filesys_lock);
}


void check_address(void *addr) {
    if (is_kernel_vaddr(addr) || addr == NULL || pml4_get_page(thread_current()->pml4, addr) == NULL)
        exit(-1);
}


void syscall_handler(struct intr_frame *f UNUSED) {
    // TODO: Your implementation goes here.
    int sys_number = f->R.rax;

    // Argument 순서
    // %rdi %rsi %rdx %r10 %r8 %r9

    switch (sys_number) {
        case SYS_HALT:
            halt();
            break;
        case SYS_EXIT:
            exit(f->R.rdi);
            break;
        case SYS_FORK:
            f->R.rax = fork(f->R.rdi);
            break;
        case SYS_EXEC:
            f->R.rax = exec(f->R.rdi);
            break;
        case SYS_WAIT:
            f->R.rax = process_wait(f->R.rdi);
            break;
        case SYS_CREATE:
            f->R.rax = create(f->R.rdi, f->R.rsi);
            break;
        case SYS_REMOVE:
            f->R.rax = remove(f->R.rdi);
            break;
        case SYS_OPEN:
            f->R.rax = open(f->R.rdi);
            break;
        case SYS_FILESIZE:
            f->R.rax = filesize(f->R.rdi);
            break;
        case SYS_READ:
            f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_WRITE:
            f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_SEEK:
            seek(f->R.rdi, f->R.rsi);
            break;
        case SYS_TELL:
            f->R.rax = tell(f->R.rdi);
            break;
        case SYS_CLOSE:
            close(f->R.rdi);
            break;
        // case SYS_DUP2:
            // f->R.rax = dup2(f->R.rdi, f->R.rsi);
            // break;
        default:
            exit(-1);
    }
}



void halt(void) {
    power_off();
}

void exit(int status) {
    struct thread *curr = thread_current();
    curr->exit_status = status;

    /** #Project 2: Process Termination Messages */
    printf("%s: exit(%d)\n", curr->name, curr->exit_status);

    thread_exit();
}

// pid_t fork(const char *thread_name) {
//     check_address(thread_name);

//     return process_fork(thread_name, NULL);
// }

int exec(const char *cmd_line) {
    check_address(cmd_line);

    off_t size = strlen(cmd_line) + 1;
    char *cmd_copy = palloc_get_page(PAL_ZERO);

    if (cmd_copy == NULL)
        return -1;

    memcpy(cmd_copy, cmd_line, size);

    if (process_exec(cmd_copy) == -1)
        return -1;

    return 0;  // process_exec 성공시 리턴 값 없음 (do_iret)
}

int wait(pid_t tid) {
    return process_wait(tid);
}

bool create(const char *file, unsigned initial_size) {
    check_address(file);

    return filesys_create(file, initial_size);
}

bool remove(const char *file) {
    check_address(file);

    return filesys_remove(file);
}

int open(const char *file) {
    check_address(file);
    struct file *newfile = filesys_open(file);

    if (newfile == NULL)
        return -1;

    int fd = process_add_file(newfile);

    if (fd == -1)
        file_close(newfile);

    return fd;
}

int filesize(int fd) {
    struct file *file = process_get_file(fd);

    if (file == NULL)
        return -1;

    return file_length(file);
}

int read(int fd, void *buffer, unsigned length) {
    struct thread *curr = thread_current();
    check_address(buffer);

    struct file *file = process_get_file(fd);

    if (file == 1) {                // 0(stdin) -> keyboard로 직접 입력
        if (curr->stdin_count == 0) /** #Project 2: Extend File Descriptor - stdin이 닫혀있을 경우 */
            return -1;

        int i = 0;  // 쓰레기 값 return 방지
        char c;
        unsigned char *buf = buffer;

        for (; i < length; i++) {
            c = input_getc();
            *buf++ = c;
            if (c == '\0')
                break;
        }

        return i;
    }

    if (file == NULL || file == STDOUT || file == STDERR)  // 빈 파일, stdout, stderr를 읽으려고 할 경우
        return -1;

    // 그 외의 경우
    off_t bytes = -1;

    lock_acquire(&filesys_lock);
    bytes = file_read(file, buffer, length);
    lock_release(&filesys_lock);

    return bytes;
}

int write(int fd, const void *buffer, unsigned length) {
    check_address(buffer);

    struct thread *curr = thread_current();
    off_t bytes = -1;

    struct file *file = process_get_file(fd);

    if (file == STDIN || file == NULL)  // stdin에 쓰려고 할 경우
        return -1;

    if (file == STDOUT) {                 // 1(stdout) -> console로 출력
        if (curr->stdout_count <= 0) /** #Project 2: Extend File Descriptor - stdout이 닫혀있을 경우 */
            return -1;

        putbuf(buffer, length);
        return length;
    }

    if (file == STDERR) {                 // 2(stderr) -> console로 출력
        if (curr->stderr_count <= 0) /** #Project 2: Extend File Descriptor - stderr이 닫혀있을 경우 */
            return -1;

        putbuf(buffer, length);
        return length;
    }

    lock_acquire(&filesys_lock);
    bytes = file_write(file, buffer, length);
    lock_release(&filesys_lock);

    return bytes;
}

void seek(int fd, unsigned position) {
    if (fd < 0)
        return;

    struct file *file = process_get_file(fd);

    if (file == NULL || (file >= STDIN && file <= STDERR))
        return;

    file_seek(file, position);
}

int tell(int fd) {
    struct file *file = process_get_file(fd);

    if (file == NULL || (file >= STDIN && file <= STDERR))
        return -1;

    return file_tell(file);
}

void close(int fd) {
    struct thread *curr = thread_current();
    struct file *file = process_get_file(fd);

    if (file == NULL)
        return;

    process_close_file(fd);

    if (file == STDIN) {
        if (curr->stdin_count != 0)
            curr->stdin_count--;

        return;
    }

    if (file == STDOUT) {
        if (curr->stdout_count != 0)
            curr->stdout_count--;

        return;
    }

    if (file == STDERR) {
        if (curr->stderr_count != 0)
            curr->stderr_count--;

        return;
    }

    if (file->dup_count == 0)
        file_close(file);
    else
        file->dup_count--;
}

// /** #Project 2: Extend File Descriptor (Extra) */
// int dup2(int oldfd, int newfd) {
//     if (oldfd < 0 || newfd < 0)
//         return -1;

//     struct file *oldfile = process_get_file(oldfd);

//     if (oldfile == NULL)
//         return -1;

//     if (oldfd == newfd)
//         return newfd;

//     struct file *newfile = process_get_file(newfd);

//     if (oldfile == newfile)
//         return newfd;

//     close(newfd);

//     newfd = process_insert_file(newfd, oldfile);

//     return newfd;
// }