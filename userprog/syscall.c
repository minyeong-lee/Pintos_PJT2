#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

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
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {  //
	// TODO: Your implementation goes here.
	/* 사용자 스택에 저장되어 있는 시스템 콜 넘버 가져오기 */
	int sys_number = f->R.rax;  //rax: 시스템 콜 넘버

	/*
		인자 들어오는 순서:
		1번째 인자: %rdi
		2번째 인자: %rsi
		3번째 인자: %rdx
		4번째 인자: %r10
		5번째 인자: %r8
		6번째 인자: %r9	
	*/
	// switch(sys_number) {
	// 	case SYS_HALT:
	// 		halt();
	// 	case SYS_EXIT:
	// 		exit(f->R.rdi);
	// 	case SYS_FORK:
	// 		fork(f->R.rdi);
	// 	case SYS_EXEC:
	// 		exec(f->R.rdi);
	// 	case SYS_WAIT:
	// 		wait(f->R.rdi);
	// 	case SYS_CREATE:
	// 		create(f->R.rdi, f->R.rsi);
	// 	case SYS_REMOVE:
	// 		remove(f->R.rdi);
	// 	case SYS_OPEN:
	// 		open(f->R.rdi);
	// 	case SYS_FILESIZE:
	// 		filesize(f->R.rdi);
	// 	case SYS_READ:
	// 		read(f->R.rdi, f->R.rsi, f->R.rdx);
		
			
	// }




	printf ("system call!\n");
	thread_exit ();
}

/* --- Project 2: User_Memory_Access ---*/
void
check_address (void *addr) {
	struct thread *t = thread_current();
	if (!is_user_vaddr(addr)||addr == NULL)
	// -> 이 경우는 유저 주소 영역 내에서도 할당되지 않는 공간 가리키는 것을 체크하지 않음
	// 그래서 pml4_get_page 를 추가해줘야!
	if (!is_user_vaddr(addr)||addr == NULL||
	pml4_get_page(t->pml4, addr) == NULL)
	{
		exit(-1);
	}
}
/* 해당 주소값이 유저 가상 주소(user_vaddr)에 해당하는지 아닌지 체크하고
   유저 영역이 아니면 종료한다
   - is_user_vaddr() 은 이미 주어진 함수임
   - pml4_get_page()는 유저 가상 주소와 대응하는 물리 주소를 확인해서 해당 물리 주소와 연결된 커널 가상 주소를 반환하거나
     만약 해당 물리 주소가 가상 주소와 매핑되지 않은 영역이면 NULL 반환
*/
/* --- Project 2: User_Memory_Access ---*/