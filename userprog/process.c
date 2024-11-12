#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	/* Clone current thread to new thread.*/
	return thread_create (name,
			PRI_DEFAULT, __do_fork, thread_current ());
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */

	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux;
	struct thread *current = thread_current ();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if;
	bool succ = true;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/

	process_init ();

	/* Finally, switch to the newly created process. */
	if (succ)
		do_iret (&if_);
error:
	thread_exit ();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
/*
	프로세스가 새로운 사용자 프로그램을 실행하도록 컨텍스트를 전환하는 역할
	- 현재 프로세스의 실행 컨텍스트를 지우고,
	  주어진 파일(사용자 프로그램)을 메모리에 로드한 후 실행을 시작함

	- 우리가 입력해주는 명령을 받기 직전에 어떤 스레드가 돌고 있었을 테니(그게 idle이든 실제로 실행 중이든)
	  process_exec()에 context switching 역할도 같이 넣어줘야 함
*/
int
process_exec (void *f_name) {
	/* 디스크에 있는 사용자 프로그램을 메모리에 올려서 실행하기 위한 요청이 들어오는 상황에 이 함수가 호출됨 */

	/* 초기화 준비 */
	char *file_name = f_name;  //프로그램 파일의 이름. f_name은 문자열인데 위에서 (void *)로 넘겨받았고, 문자열로 인식하기 위해서 char * 로 변환해줘야 함
	bool success; //프로그램 로드 성공 여부

	/* --- Project 2: Command_line_parsing ---*/
	char file_name_copy[128];  //스택에 저장
	//원본 문자열을 parsing하면 다른 함수에서 원본 문자열을 쓸 여지가 있으므로 복사본 생성
	memcpy(file_name_copy, file_name, strlen(file_name)+1);  //strlen에 +1을 하는 이유? 원래 문자열에는 \n이 들어가는데, strlen에서는 \n 앞까지만 읽고 끝내기 때문. 전체를 들고오기 위해 +1함
	/* --- Project 2: Command_line_parsing ---*/


	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	/* 레지스터 프레임 설정 */
	struct intr_frame _if; //인터럽트 스택 프레임을 나타내는 구조체 (이 프레임은 사용자 프로그램을 실행할 때 필요한 CPU 레지스터 상태를 저장하는 데 사용됨)
	_if.ds = _if.es = _if.ss = SEL_UDSEG;  //데이터 세그먼트, 추가 세그먼트, 스택 세그먼트 레지스터를 사용자 데이터 세그먼트(SEL_UDSEG)로 설정함
	_if.cs = SEL_UCSEG; //코드 세그먼트를 사용자 코드 세그먼트로 설정
	_if.eflags = FLAG_IF | FLAG_MBS; //인터럽트 플래그와 머신 상태 플래그를 활성화하여, 사용자 프로그램의 실행 환경 설정
	
	
	/* We first kill the current context */
	/* 컨텍스트 정리 */
	process_cleanup (); 
	//현재 프로세스의 기존 컨텍스트 정리하여, 새로운 프로그램을 실행할 준비를 함 (ex. 기존 메모리, 파일 디스크립터 등을 해제) => 현재 스레드의 이전 실행 상태 지우기 위함
	//새로운 실행 파일을 현재 스레드에 담기 전에 먼저 현재 process에 담긴 context를 지워준다
	//지운다? => 현재 프로세스에 할당된 page directory를 지운다는 뜻

	/* And then load the binary */
	/* 프로그램 로드 */
	success = load (file_name, &_if); //주어진 프로그램(file_name)을 메모리에 로드하여 _if 프레임에 초기화함. 성공 여부가 success에 저장됨
	//load 함수로 프로그램을 메모리에 로드하면, _if에 실행 시작 지점(엔트리 포인트)이 설정됨
	//success는 bool type이니까 load에 성공하면 1, 실패하면 0 반환
	

	/* If load failed, quit. */
	/* 할당 해제 및 성공 확인 */
	palloc_free_page (file_name); //file_name이 할당받은 페이지를 해제함. 메모리 누수 방지를 위해서임 (프로그램 로드가 실패한 경우에만 메모리 해제함)
	//file_name은 프로그램 파일 받기 위해 만든 임시변수로, load 끝나면 메모리 반환
	if (!success)
		return -1; //만약 프로그램 로드 실패하면 -1 반환하여 오류 알림
	//성공 여부에 따라 함수를 종료할지, 다음 단계로 진행할지 결정함

	/* Start switched process. */
	/* 프로그램 실행 전환 */
	//모든 설정이 완료된 후
	do_iret (&_if); //do_iret()함수 호출하여 _if에 저장된 레지스터 상태로 전환하고, 사용자 프로그램의 실행을 시작함 (설정된 _if 상태로 사용자 모드에서 프로그램 실행을 시작)
	NOT_REACHED (); //이 위치에는 프로그램이 도달하지 않아야 함. 만약 도달한다면, 논리 오류 발생했음을 의미함

	//do_iret은 커널 모드에서 사용자 모드로 전환하는 기능으로, _if에 설정된 레지스터 상태에 따라 실제 프로그램이 사용자 모드에서 실행됨
}
// 이 함수는 새로운 사용자 프로그램을 로드하고 실행하는 함수임
// 기존의 프로세스 상태를 정리한 후, 주어진 프로그램을 사용자 모드에서 실행할 수 있도록 설정



/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	return -1;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */

	process_cleanup ();
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
/*
	load 함수는 ELF 형식의 실행 파일을 현재 스레드에 로드하고, 프로그램의 엔트리 포인트와 스택을 설정함
*/
static bool
load (const char *file_name, struct intr_frame *if_) {  //if_는 프로그램 실행 시 사용할 초기 인터럽트 프레임 
	/* 필요한 변수 선언 */
	struct thread *t = thread_current (); //현재 실행 중인 스레드의 포인터를 t에 저장 (이 스레드에 프로그램이 로드됨)
	struct ELF ehdr; //ELF 헤더 선언
	struct file *file = NULL; //파일 포인터 선언
	off_t file_ofs; //파일 오프셋 선언
	bool success = false; //성공 여부
	int i; //반복문 변수 선언

	/* Allocate and activate page directory. */
	/* 페이지 테이블 생성 및 활성화 */
	t->pml4 = pml4_create (); //새로운 페이지 테이블 생성하여 t->pml4에 할당
	if (t->pml4 == NULL)  //실패 시 done 레이블로 이동하여 함수가 종료됨
		goto done;
	process_activate (thread_current ()); //생성된 페이지 테이블을 활성화하여 메모리 맵을 설정

	/* Open executable file. */
	/* 사용자 프로그램 파일 열기 */
	file = filesys_open (file_name); //file_name을 열고
	if (file == NULL) { //실패 시 오류 메시지 출력하고 done 레이블로 이동하여 함수 종료
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Read and verify executable header. */
	/* ELF 헤더 읽고 검증 */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr 
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) { // 파일에서 ELF 헤더를 읽고, ELF 파일인지와 헤더가 유효한지 확인
		printf ("load: %s: error loading executable\n", file_name); //조건이 하나라도 만족되지 않으면 오류 메시지 출력하고 done으로 이동
		goto done;
	}

	/* Read program headers. */
	/* 프로그램 헤더 테이블 읽기 */
	file_ofs = ehdr.e_phoff; //프로그램 헤더 오프셋을 file_ofs에 설정
	for (i = 0; i < ehdr.e_phnum; i++) { //프로그램 헤더의 개수(ehdr.e_phnum)만큼 반복하여 각 프로그램 헤더를 읽기
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file)) //파일 오프셋이 유효한지 확인한 후,
			goto done;
		file_seek (file, file_ofs); //프로그램 헤더의 위치로 파일 포인터를 이동

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr) //프로그램 헤더를 읽고, 읽기에 실패하면
			goto done; //done으로 이동
		file_ofs += sizeof phdr; //이후 오프셋을 다음 프로그램 헤더 위치로 이동
		switch (phdr.p_type) { //프로그램 헤더의 p_type에 따라 처리를 다르게 함
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */ //무시
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done; //PT_DYNAMIC, PT_INTERP 등은 ELF 로더에서 지원하지 않으므로 done으로 이동
			case PT_LOAD: //PT_LOAD 유형의 세그먼트가 유효한지 검사
				if (validate_segment (&phdr, file)) { //유효하면 메모리에 로드하는 설정 시작!!
					bool writable = (phdr.p_flags & PF_W) != 0; //writable은 해당 세그먼트가 쓰기 가능한지 나타냄
					uint64_t file_page = phdr.p_offset & ~PGMASK; //file_page는 파일에서 읽어올 페이지 위치
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK; //mem_page는 메모리에서 세그먼트 시작 주소
					uint64_t page_offset = phdr.p_vaddr & PGMASK; //page_offset은 페이지 오프셋
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) { //세그먼트의 파일 크기가 0보다 크면
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz; //read_bytes에 읽을 바이트 수 저장
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE) //나머지는 0으로 채움
								- read_bytes);
					} else { //세그먼트의 파일 크기가 0이면 모든 바이트를 0으로 설정
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					/* 파일 세그먼트 로드 */
					//프로그램 헤더가 유효하면
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable)) //load_segment 함수를 호출해 파일의 특정 세그먼트를 메모리에 로드함 => 이때 파일 오프셋, 메모리 주소, 메모리 주소, 읽을 바이트 수 등을 계산하여 디스크에서 메모리로 복사
						goto done; //실패 시 done으로 이동
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_)) //프로그램의 유저 스택 설정
		goto done; //실패 시 done으로 이동

	/* Start address. */
	if_->rip = ehdr.e_entry; //인터럽트 프레임의 rip를 실행 시작 지점(엔트리 포인트)으로 설정

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */
	/* 커맨드 라인에서의 명렁어 실행 */
	//첫 번째 단어는 프로그램 이름, 그 다음부터 첫 번째 인자, 두 번째 인자가 옴









	success = true; //프로그램 로드가 성공했음을 나타내기 위해 success를 true로 설정

done:
	/* We arrive here whether the load is successful or not. */
	file_close (file); //파일 닫고
	return success; //로드 성공 여부 반환
}
/*
load 함수는 실제로 디스크에서 사용자 프로그램을 읽어서 스레드의 주소 공간(메모리)에 로드하는 작업을 수행함
=> 이렇게 함으로써, 스레드는 프로그램의 코드와 데이터를 메모리에서 사용할 수 있게 되고, 이후 사용자 모드에서 프로그램이 실행될 수 있다
*/


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */
