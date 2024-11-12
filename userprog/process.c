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

/*
목적:
현재 실행 중인 스레드의 초기화 작업을 수행하는 함수입니다.
이 함수는 주로 initd와 같은 프로세스가 시작될 때, 그 프로세스에 대한 초기화 작업을 위한 준비를 하는 데 사용됩니다.
역할:
process_init은 thread_current()를 호출하여 현재 스레드를 얻은 후, 해당 스레드에 대해 필요한 초기화 작업을 수행할 수 있는 준비를 합니다.
하지만 현재 코드에서는 그 이후에 구체적인 작업이 없어, 실제 초기화가 필요한 부분은 다른 곳에서 처리될 가능성이 큽니다.
*/
static void
process_init (void)
{
    struct thread *current = thread_current (); // 현재 실행 중인 스레드(즉, 현재 프로세스)의 정보를 얻습니다.
    
	// 현재 스레드를 초기화하는 작업은 추후 추가될 수 있습니다.
}


/* 새로운 스레드를 생성하여 사용자 프로그램인 “initd”를 실행하고, 이를 위해 필요한 파일 이름을 준비하고, 초기화하는 역할을 합니다.
이 과정에서 인자 파싱과 메모리 할당을 처리하며, 실패 시 적절한 메모리 해제를 수행 */
tid_t process_create_initd(const char *file_name)
{
    char *fn_copy;
    tid_t tid;

    /* 파일 이름(FILE_NAME)을 복사합니다.
     * 그렇지 않으면 호출자와 load() 사이에 경쟁 조건(race condition)이 발생할 수 있습니다. */
    fn_copy = palloc_get_page(0);  			// 파일 이름을 저장할 메모리를 할당합니다.
    if (fn_copy == NULL)
        return TID_ERROR;  					// 메모리 할당에 실패하면 TID_ERROR를 반환합니다.
    strlcpy(fn_copy, file_name, PGSIZE);  	// file_name을 fn_copy에 복사합니다.

    char *save_ptr;
    strtok_r(file_name, " ", &save_ptr);  	// file_name을 공백을 기준으로 토큰화합니다.

    /* 새 스레드를 생성하여 FILE_NAME을 실행하도록 합니다. */
    tid = thread_create(file_name, PRI_DEFAULT, initd, fn_copy);  // 새로운 스레드를 생성하여 initd를 실행하고 fn_copy를 인자로 전달합니다.
    if (tid == TID_ERROR)
        palloc_free_page(fn_copy);  		// 스레드 생성에 실패하면 할당한 메모리를 해제합니다.
    return tid;  							// 생성된 스레드의 ID를 반환합니다.
}


/* 
 * initd 함수는 첫 번째 사용자 프로세스를 시작하는 스레드 함수입니다. 
 * 이 함수는 초기화된 프로세스(`initd`)를 실행하도록 설계되어 있습니다.
 */
static void
initd (void *f_name)
{
    #ifdef VM
        // 가상 메모리 기능이 활성화된 경우, 현재 스레드의 보조 페이지 테이블 초기화
        supplemental_page_table_init (&thread_current ()->spt);
    #endif

    // 현재 프로세스에 대한 초기화 작업 수행
    process_init ();

    // f_name에 해당하는 프로그램 실행
    if (process_exec (f_name) < 0)
        // 실행 실패 시 시스템을 비정상 종료시킴
        PANIC("Fail to launch initd\n");

    // 만약 process_exec이 성공적으로 실행되었다면, 이 코드는 도달할 수 없음
    NOT_REACHED ();  
}


/* 
인자
`name`: 생성할 스레드의 이름입니다. 보통 부모 프로세스의 이름과 관련이 있습니다.
`if_`: 부모의 인터럽트 프레임을 나타내는 인자이지만, 이 함수에서는 사용되지 않기 때문에 `UNUSED`로 표시됩니다.

이 함수의 목적은 현재 실행중인 프로세스를 복제하여 새로운 스레드(자식 프로세스)를 시작하는 것입니다.
*/
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED)
{
    /* 부모 스레드를 복제하여 자식 스레드를 생성하는 함수 `thread_create` 호출 */
    return thread_create (name,    						 // 자식 스레드의 이름
            PRI_DEFAULT, __do_fork, thread_current ());  // 우선순위와 실행 함수 설정
}


#ifndef VM
/* 부모 프로세스의 주소 공간을 자식 프로세스로 복제하는 역할을 합니다.
이 함수는 pml4_for_each를 통해 부모의 페이지 테이블을 반복하면서, 부모의 각 페이지를 자식 프로세스의 페이지 테이블에 복제합니다.
이 함수는 프로젝트 2에서 사용되며, 프로세스가 fork()를 호출할 때 자식 프로세스의 주소 공간을 설정하는 데 필요 */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
    struct thread *current = thread_current ();     // 현재 스레드를 가져옵니다. (자식 프로세스)
    struct thread *parent = (struct thread *) aux;  // 부모 스레드를 가져옵니다.
    void *parent_page;  							// 부모 페이지
    void *newpage;  								// 자식 프로세스에 할당될 새로운 페이지
    bool writable;  								// 부모 페이지가 쓰기 가능한지 여부를 나타내는 변수

    /* 1. TODO: 만약 부모 페이지가 커널 페이지라면 즉시 반환합니다. */
    // 커널 페이지는 자식 프로세스에 복제할 필요가 없으므로 처리하지 않고 바로 반환합니다.

    /* 2. 부모의 페이지 테이블에서 가상 주소(va)를 통해 부모 페이지를 찾아옵니다. */
    parent_page = pml4_get_page (parent->pml4, va);  // 부모의 페이지 테이블에서 가상 주소에 해당하는 페이지를 가져옵니다.

    /* 3. TODO: 자식 프로세스를 위한 새로운 PAL_USER 페이지를 할당하고, 
     * NEWPAGE 변수에 그 주소를 설정합니다. */
    // 자식 프로세스가 사용할 새로운 사용자 페이지를 할당해야 합니다.

    /* 4. TODO: 부모 페이지를 새로운 페이지로 복제하고,
     * 부모 페이지가 쓰기 가능한지 여부를 확인하여 쓰기 권한을 설정합니다. */
    // 부모 페이지를 자식 페이지로 복제한 후, 부모 페이지가 쓰기 가능한지 확인하고,
    // 자식 페이지가 쓰기 가능한지 여부를 설정합니다.

    /* 5. 새로운 페이지를 자식 프로세스의 페이지 테이블에 추가합니다. */
    if (!pml4_set_page (current->pml4, va, newpage, writable)) {  // 자식 프로세스의 페이지 테이블에 페이지를 추가합니다.
        /* 6. TODO: 페이지 삽입에 실패한 경우, 오류 처리를 합니다. */
        // 페이지를 자식 프로세스의 페이지 테이블에 삽입하는 데 실패하면 적절한 오류 처리를 해야 합니다.
    }
    return true;  // 페이지 복제 작업이 성공적으로 완료되었음을 반환합니다.
}
#endif


/* 부모 프로세스의 실행 컨텍스트를 복제하여 새로운 자식 프로세스를 생성하는 역할을 합니다.
이 함수는 fork() 시스템 호출을 구현하는 과정에서 자식 프로세스의 초기 상태를 설정하는 데 사용됩니다.
부모 프로세스의 페이지 테이블, 파일 객체 등 중요한 리소스를 복제한 후, 자식 프로세스로 전환 */
static void
__do_fork (void *aux)
{
    struct intr_frame if_;   						// 인터럽트 프레임을 저장할 구조체
    struct thread *parent = (struct thread *) aux;  // 부모 스레드
    struct thread *current = thread_current ();     // 현재 자식 스레드
    struct intr_frame *parent_if;   				// 부모 프로세스의 인터럽트 프레임을 저장할 포인터
    bool succ = true;   							// 성공 여부를 나타내는 변수

    /* 1. 부모 프로세스의 인터럽트 프레임을 자식 스레드로 복사합니다. */
    memcpy (&if_, parent_if, sizeof (struct intr_frame));

    /* 2. 부모의 페이지 테이블을 자식 스레드로 복제합니다. */
    current->pml4 = pml4_create();  // 자식 스레드를 위한 새로운 페이지 테이블 생성
    if (current->pml4 == NULL)
        goto error;  				// 페이지 테이블 생성 실패 시 오류 처리

    process_activate (current);  	// 자식 프로세스를 활성화합니다.

#ifdef VM
    // 가상 메모리 사용 시, 부모의 보조 페이지 테이블을 복제합니다.
    supplemental_page_table_init (&current->spt);  					  // 자식 프로세스를 위한 보조 페이지 테이블 초기화
    if (!supplemental_page_table_copy (&current->spt, &parent->spt))  // 부모의 보조 페이지 테이블 복제
        goto error;  // 복제 실패 시 오류 처리
#else
    // 가상 메모리가 아닌 경우, 부모의 페이지 테이블을 복제합니다.
    if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
        goto error;  // 페이지 복제 실패 시 오류 처리
#endif

    /* TODO: 부모 프로세스의 파일 객체를 복제하는 작업이 추가되어야 합니다. */
    /* 부모 프로세스의 열린 파일, 파일 디스크립터 등을 자식 프로세스에 복제하는 코드를 구현해야 합니다. */

    process_init ();  // 자식 프로세스에 대한 초기화 작업 수행

    /* 마지막으로, 자식 프로세스로 컨텍스트 전환합니다. */
    if (succ)
        do_iret (&if_);  // 인터럽트 프레임을 사용해 자식 프로세스로 전환
error:
    thread_exit ();  	 // 오류 발생 시, 스레드를 종료
}


int process_exec(void *f_name)
{
    char *file_name = f_name;
    bool success;

    /* 현재 스레드의 실행 정보(intr_frame)를 설정 */
    struct intr_frame _if;
    _if.ds = _if.es = _if.ss = SEL_UDSEG;  	// 사용자 데이터 세그먼트
    _if.cs = SEL_UCSEG;  					// 사용자 코드 세그먼트
    _if.eflags = FLAG_IF | FLAG_MBS;  		// 인터럽트 플래그 설정

    /* 기존 실행 상태 정리 */
    process_cleanup();

	char *parse[64];  // 인자를 저장할 배열. 최대 64개의 인자를 저장할 수 있음.
	char *token, *save_ptr;  // token은 현재 파싱 중인 인자를 저장하고, save_ptr은 strtok_r의 상태를 저장
	int count = 0;  // 파싱된 인자의 개수를 셈. 인자 배열에 저장된 총 인자 개수를 추적

    // 공백을 기준으로 문자열 파싱
    for (token = strtok_r(file_name, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr))
        parse[count++] = token;

    /* 이진 파일 로드 */
    success = load(file_name, &_if);  // 이진 파일을 메모리에 로드
    // 로드 후 실행할 함수 주소와 스택 포인터 초기화

    argument_stack(parse, count, &_if.rsp);  // 인자를 스택에 올리기
    _if.R.rdi = count;  					 // argc
    _if.R.rsi = (char *)_if.rsp + 8;  		 // argv

    hex_dump(_if.rsp, _if.rsp, USER_STACK - (uint64_t)_if.rsp, true);  // 스택 덤프 출력

    /* 로드 실패 시 종료 */
    palloc_free_page(file_name);  // 파일 이름에 할당된 메모리 해제
    if (!success)
        return -1;  			  // 로드 실패 시 -1 반환

    /* 새 프로세스 실행 */
    do_iret(&_if);  			  // 새 프로세스 컨텍스트로 전환
    NOT_REACHED();  			  // 정상적으로 실행되면 이 지점에 오지 않음
}


void argument_stack(char **parse, int count, void **rsp) // 주소를 전달받았으므로 이중 포인터 사용
{
    // 프로그램 이름, 인자 문자열 push
    for (int i = count - 1; i > -1; i--)
    {
        for (int j = strlen(parse[i]); j > -1; j--)
        {
            (*rsp)--;                      // 스택 주소 감소
            **(char **)rsp = parse[i][j]; // 주소에 문자 저장
        }
        parse[i] = *(char **)rsp; // parse[i]에 현재 rsp의 값 저장해둠(지금 저장한 인자가 시작하는 주소값)
    }

    // 정렬 패딩 push
    int padding = (int)*rsp % 8;
    for (int i = 0; i < padding; i++)
    {
        (*rsp)--;
        **(uint8_t **)rsp = 0; // rsp 직전까지 값 채움
    }

    // 인자 문자열 종료를 나타내는 0 push
    (*rsp) -= 8;
    **(char ***)rsp = 0; // char* 타입의 0 추가

    // 각 인자 문자열의 주소 push
    for (int i = count - 1; i > -1; i--)
    {
        (*rsp) -= 8; // 다음 주소로 이동
        **(char ***)rsp = parse[i]; // char* 타입의 주소 추가
    }

    // return address push
    (*rsp) -= 8;
    **(void ***)rsp = 0; // void* 타입의 0 추가
}


/* 
자식 프로세스가 종료될 때까지 기다리고, 종료 상태를 반환하는 역할을 합니다.
자식 프로세스의 종료 상태를 확인하고, 종료된 자식 프로세스에 대한 정보를 가져옵니다.
이 함수는 wait() 시스템 호출을 구현하는 데 사용

이 함수는 문제 2-2에서 구현될 예정입니다. 현재로서는 아무 작업도 하지 않습니다.
 */
int
process_wait (tid_t child_tid UNUSED)
{
	/* XXX: 힌트) Pintos에서는 `process_wait(initd)`가 호출되면 시스템이 종료됩니다.
	 * XXX:       `process_wait`를 구현하기 전에 무한 루프를 추가하는 것이 좋습니다. */
	for (int i = 0; i < 100000000; i++)
  	{
  	}
	return -1;
}


/* 
process_exit 함수는 프로세스가 종료될 때 호출됩니다.
이 함수는 스레드 종료 시 프로세스가 종료될 때 호출되며, 프로세스의 정리 작업을 수행합니다.
이 함수는 스레드 종료를 처리하는 thread_exit() 함수에 의해 호출되며, 프로세스 종료에 관련된 자원 정리와 프로세스 종료 메시지 등을 처리
 */
void
process_exit (void)
{
	struct thread *curr = thread_current ();  // 현재 실행 중인 스레드를 가져옵니다.

	/* TODO: 여기서 프로세스 종료 메시지를 구현해야 합니다.
	 * 프로젝트2의 문서에 따라 종료 메시지를 출력하도록 합니다. */
	
	/* TODO: 프로세스 자원 정리 작업을 이곳에 구현해야 합니다. */
	process_cleanup ();  // 프로세스와 관련된 자원 정리를 수행합니다.
}


/* 현재 프로세스가 종료될 때 프로세스와 관련된 모든 자원을 해제하는 역할을 합니다.
이 함수는 페이지 테이블, 메모리, 그리고 가상 메모리 시스템에서 사용한 리소스를 정리 */
static void
process_cleanup (void)
{
	struct thread *curr = thread_current ();  // 현재 실행 중인 스레드(프로세스)를 가져옵니다.

#ifdef VM
	// VM(가상 메모리)을 사용할 경우, 보조 페이지 테이블을 해제합니다.
	supplemental_page_table_kill (&curr->spt);  // 현재 스레드의 보조 페이지 테이블(spt)을 해제합니다.
#endif

	uint64_t *pml4;  // 부모 프로세스의 페이지 테이블을 가리킬 포인터
	/* 현재 프로세스의 페이지 디렉터리를 삭제하고, 
	 * 커널 전용 페이지 디렉터리로 전환합니다. */
	pml4 = curr->pml4;  // 현재 스레드의 pml4(페이지 맵 레벨 4) 포인터를 가져옵니다.
	if (pml4 != NULL) {
		/* 페이지 디렉터리를 변경하는 순서가 중요합니다. 
		 * 먼저 cur->pagedir을 NULL로 설정한 뒤 페이지 디렉터리를 전환해야 합니다. 
		 * 이렇게 해야 타이머 인터럽트가 발생하더라도 잘못된 페이지 디렉터리를 참조하지 않게 됩니다.
		 * 페이지 디렉터리를 전환하기 전에 활성화해야 합니다. 그렇지 않으면
		 * 아직 해제되지 않은 디렉터리의 주소를 참조할 수 있기 때문입니다. */
		curr->pml4 = NULL;  // 현재 프로세스의 pml4를 NULL로 설정하여 더 이상 참조하지 않도록 합니다.
		pml4_activate (NULL);  // 활성화된 페이지 디렉터리를 NULL로 설정하여 더 이상 사용할 수 없게 만듭니다.
		pml4_destroy (pml4);  // 페이지 디렉터리를 삭제합니다.
	}
}


/* 새로운 스레드(즉, 문맥 교환 후 실행될 스레드)가 실행되기 전에 CPU의 상태를 설정하는 역할을 합니다.
이 함수는 문맥 교환(context switch)이 발생할 때마다 호출됩니다. 주로 페이지 테이블 활성화와 커널 스택 설정을 처리. */
void
process_activate (struct thread *next)
{
	/* 스레드의 페이지 테이블을 활성화합니다. */
	pml4_activate (next->pml4);  // 'next' 스레드의 페이지 테이블을 활성화합니다.

	/* 스레드의 커널 스택을 설정하여 인터럽트 처리에 사용합니다. */
	tss_update (next); 			 // 'next' 스레드의 커널 스택을 설정하여 인터럽트 처리에 사용할 준비를 합니다.
}


/* ELF 바이너리를 로드합니다. 다음 정의는 ELF 사양(ELF1)에서 거의 그대로 가져온 것입니다. */
/* ELF 타입들. [ELF1] 1-2에서 참조하세요. */
#define EI_NIDENT 16  // ELF 헤더의 식별자 길이를 정의합니다. (16바이트)

/* 세그먼트 유형들 */
#define PT_NULL    0            /* 무시합니다. */
#define PT_LOAD    1            /* 로드 가능한 세그먼트입니다. */
#define PT_DYNAMIC 2            /* 동적 연결 정보입니다. */
#define PT_INTERP  3            /* 동적 로더의 이름입니다. */
#define PT_NOTE    4            /* 보조 정보입니다. */
#define PT_SHLIB   5            /* 예약된 세그먼트입니다. */
#define PT_PHDR    6            /* 프로그램 헤더 테이블입니다. */
#define PT_STACK   0x6474e551   /* 스택 세그먼트입니다. */

/* 세그먼트 플래그들 */
#define PF_X 1          /* 실행 가능. */
#define PF_W 2          /* 쓰기 가능. */
#define PF_R 4          /* 읽기 가능. */


/* ELF 실행 파일의 헤더. [ELF1] 1-4에서 1-8까지 참조.
 * ELF 바이너리의 맨 앞부분에 위치합니다. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];   // ELF 식별자 (파일 형식 식별)
	uint16_t e_type;                    // 파일 타입 (예: 실행 파일, 공유 라이브러리 등)
	uint16_t e_machine;                 // 머신 아키텍처 (예: x86_64)
	uint32_t e_version;                 // ELF 버전
	uint64_t e_entry;                   // 프로그램의 시작 주소 (진입점)
	uint64_t e_phoff;                   // 프로그램 헤더 테이블의 오프셋
	uint64_t e_shoff;                   // 섹션 헤더 테이블의 오프셋
	uint32_t e_flags;                   // ELF 특수 플래그
	uint16_t e_ehsize;                  // ELF 헤더 크기 (바이트 단위)
	uint16_t e_phentsize;               // 프로그램 헤더 엔트리 크기 (바이트 단위)
	uint16_t e_phnum;                   // 프로그램 헤더의 수
	uint16_t e_shentsize;               // 섹션 헤더 엔트리 크기 (바이트 단위)
	uint16_t e_shnum;                   // 섹션 헤더의 수
	uint16_t e_shstrndx;                // 섹션 이름 문자열 테이블의 인덱스
};


/* ELF64 프로그램 헤더. 각 프로그램 세그먼트의 정보가 포함됩니다. */
struct ELF64_PHDR {
	uint32_t p_type;      // 세그먼트의 유형
	uint32_t p_flags;     // 세그먼트의 플래그
	uint64_t p_offset;    // 파일에서 세그먼트의 시작 오프셋
	uint64_t p_vaddr;     // 세그먼트가 메모리에 로드될 가상 주소
	uint64_t p_paddr;     // 세그먼트가 메모리에 로드될 물리 주소 (필요시)
	uint64_t p_filesz;    // 파일에서의 세그먼트 크기
	uint64_t p_memsz;     // 메모리에서의 세그먼트 크기
	uint64_t p_align;     // 세그먼트의 정렬 값
};


/* 약어 정의 */
#define ELF ELF64_hdr  		// ELF64_hdr를 ELF로 간단하게 호출할 수 있도록 약어 정의
#define Phdr ELF64_PHDR  	// ELF64_PHDR을 Phdr로 간단하게 호출할 수 있도록 약어 정의

/* 스택을 설정하는 함수 */
static bool setup_stack (struct intr_frame *if_);

/* 세그먼트가 유효한지 검증하는 함수 */
static bool validate_segment (const struct Phdr *phdr, struct file *file);

/* 세그먼트를 로드하는 함수 */
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable);


/* ELF 실행 파일을 현재 스레드의 주소 공간에 로드하는 중요한 역할을 합니다.
주어진 **파일 이름(file_name)**을 통해 ELF 파일을 열고, 그 파일의 헤더를 읽고, 프로그램 세그먼트를 메모리에 적재한 뒤, 실행을 위한 설정을 완료합니다.*/
static bool load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();   // 현재 스레드를 가져옵니다.
	struct ELF ehdr;  						// ELF 헤더 구조체
	struct file *file = NULL;  				// 파일 포인터
	off_t file_ofs;  						// 파일 오프셋
	bool success = false;  					// 로드 성공 여부
	int i;  								// 반복문을 위한 변수

	/* 페이지 디렉토리 할당 및 활성화 */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;  					    // 페이지 디렉토리 할당에 실패하면 종료
	process_activate (thread_current ());   // 현재 스레드를 활성화

	/* 실행 파일 열기 */
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);  // 파일 열기 실패
		goto done;
	}

	/* ELF 헤더 읽기 및 검증 */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)    // ELF 마법 숫자 확인
			|| ehdr.e_type != 2  							// 실행 파일 타입인지 확인
			|| ehdr.e_machine != 0x3E 						// amd64 아키텍처 확인
			|| ehdr.e_version != 1  						// ELF 버전 확인
			|| ehdr.e_phentsize != sizeof (struct Phdr)  	// 프로그램 헤더 크기 확인
			|| ehdr.e_phnum > 1024) {  						// 프로그램 헤더의 개수가 너무 많으면 오류
		printf ("load: %s: error loading executable\n", file_name);  // ELF 파일 로드 오류
		goto done;
	}

	/* 프로그램 헤더 읽기 */
	file_ofs = ehdr.e_phoff;  	// 프로그램 헤더의 오프셋
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;  		// 프로그램 헤더 구조체

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;  		// 오프셋이 잘못되었으면 오류
		file_seek (file, file_ofs);  // 파일에서 해당 위치로 이동

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;  		// 헤더 읽기 실패
		file_ofs += sizeof phdr;  // 다음 헤더로 이동
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* 이 세그먼트는 무시합니다. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;  // 동적 링크 등은 처리하지 않습니다.
			case PT_LOAD:
				/* 로드 가능한 세그먼트 */
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;  	// 쓰기 가능 여부 확인
					uint64_t file_page = phdr.p_offset & ~PGMASK;   // 파일 오프셋
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;  	// 메모리 가상 주소
					uint64_t page_offset = phdr.p_vaddr & PGMASK;  	// 페이지 오프셋
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* 일반 세그먼트:
						 * 파일에서 읽은 부분을 메모리에 로드하고 나머지는 0으로 초기화 */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* 전부 0으로 초기화된 세그먼트 */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;  // 세그먼트 로드 실패
				}
				else
					goto done;  // 세그먼트 검증 실패
				break;
		}
	}

	/* 스택 설정 */
	if (!setup_stack (if_))
		goto done;  // 스택 설정 실패

	/* 시작 주소 설정 */
	if_->rip = ehdr.e_entry;  // ELF 실행 파일의 진입점 주소 설정

	/* TODO: 여기에 인자 전달 구현 (예: 명령줄 인자 처리) */

	success = true;

done:
	/* 성공 여부와 관계없이 파일을 닫고 리턴 */
	file_close (file);
	return success;
}


/* ELF 파일 내에서 프로그램 헤더(Phdr)가 유효한 로드 가능한 세그먼트인지 확인합니다. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
    /* 1. p_offset과 p_vaddr가 동일한 페이지 오프셋을 가져야 합니다. 
       p_offset은 파일 내에서 세그먼트가 시작하는 위치를 나타내며,
       p_vaddr는 메모리에서 해당 세그먼트가 시작하는 가상 주소입니다. 
       이 두 값은 페이지 크기(PGMASK)로 나누어 떨어져야 합니다. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
        return false;  // 오프셋 불일치로 로드 불가

    /* 2. p_offset은 파일 내에서 유효한 범위에 있어야 합니다. 
       p_offset이 파일의 길이보다 크다면 해당 세그먼트는 잘못된 오프셋입니다. */
    if (phdr->p_offset > (uint64_t) file_length(file))
        return false;  // 파일 내 범위를 벗어난 오프셋

    /* 3. p_memsz는 p_filesz보다 크거나 같아야 합니다. 
       p_filesz는 파일에서 실제로 읽을 크기이고, p_memsz는 세그먼트가 차지하는 메모리 크기입니다. */
    if (phdr->p_memsz < phdr->p_filesz)
        return false;  // 메모리 크기가 파일 크기보다 작으면 잘못된 세그먼트

    /* 4. 세그먼트가 비어있으면 안 됩니다. 
       p_memsz가 0이면 세그먼트가 비어있는 것이므로 로드할 수 없습니다. */
    if (phdr->p_memsz == 0)
        return false;  // 비어있는 세그먼트

    /* 5. 가상 메모리 주소는 사용자 주소 공간 내에 있어야 합니다. 
       p_vaddr는 세그먼트가 메모리에서 시작하는 주소입니다. */
    if (!is_user_vaddr((void *) phdr->p_vaddr))
        return false;  // 사용자 주소 공간 외부 주소

    if (!is_user_vaddr((void *) (phdr->p_vaddr + phdr->p_memsz)))
        return false;  // 사용자 주소 공간 외부 주소

    /* 6. 세그먼트가 커널 주소 공간을 넘지 않도록 해야 합니다. 
       세그먼트의 끝 주소가 가상 주소 범위를 벗어나면 안 됩니다. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
        return false;  // 주소가 오버플로우하여 커널 공간을 넘음

    /* 7. 페이지 0을 매핑하지 않도록 합니다. 
       페이지 0은 null 포인터와 관련된 오류를 방지하기 위해 매핑을 허용하지 않습니다. */
    if (phdr->p_vaddr < PGSIZE)
        return false;  // 페이지 0을 매핑하지 않도록 금지

    /* 8. 모든 조건을 만족하면 세그먼트는 로드 가능한 유효한 세그먼트입니다. */
    return true;  // 유효한 세그먼트
}


#ifndef VM
/* 이 코드 블록은 프로젝트 2에서만 사용됩니다.
 * 전체 프로젝트 2를 위해 함수를 구현하려면
 * #ifndef 매크로 밖에서 구현하십시오. */

/* load() 헬퍼 함수들. */
static bool install_page (void *upage, void *kpage, bool writable);

/* 세그먼트를 FILE에서 OFS 오프셋부터 UPAGE 주소에서 로드합니다.
 * 총 READ_BYTES + ZERO_BYTES 바이트의 가상 메모리가 초기화됩니다. 다음과 같이:
 *
 * - READ_BYTES 바이트는 OFS 오프셋에서 시작하여 UPAGE 주소로 FILE에서 읽어야 합니다.
 *
 * - ZERO_BYTES 바이트는 UPAGE + READ_BYTES 이후의 메모리 영역을 0으로 초기화해야 합니다.
 *
 * 이 함수가 초기화하는 페이지는 WRITABLE이 true일 경우 사용자 프로세스에서 쓰기 가능해야 하고,
 * 그렇지 않으면 읽기 전용이어야 합니다.
 *
 * 성공하면 true를 반환하고, 메모리 할당 오류나 디스크 읽기 오류가 발생하면 false를 반환합니다. */


/* ELF 파일에서 세그먼트를 로드하는 load_segment 함수입니다.
각 세그먼트는 가상 주소에서 실행되기 위해 메모리에 읽혀지고, 필요하다면 0으로 채워집니다 */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	// read_bytes + zero_bytes는 페이지 크기(4KB)의 배수여야 함을 보장합니다.
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	// upage가 페이지의 시작 주소여야 하므로 offset이 0이어야 합니다.
	ASSERT (pg_ofs (upage) == 0);
	// 파일 오프셋이 페이지 크기의 배수여야 함을 확인합니다.
	ASSERT (ofs % PGSIZE == 0);

	// 파일에서 지정된 오프셋으로 파일 포인터를 이동시킵니다.
	file_seek (file, ofs);

	// read_bytes나 zero_bytes가 남아있는 동안 반복합니다.
	while (read_bytes > 0 || zero_bytes > 0) {
		/* 이 페이지를 채우기 위해 얼마나 읽을지 계산합니다.
		 * 우리는 FILE에서 PAGE_READ_BYTES 바이트를 읽고,
		 * 남은 부분을 0으로 채웁니다. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* 메모리 페이지를 할당합니다. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;  // 메모리 할당 실패 시 false 반환

		/* 페이지를 파일에서 읽어옵니다. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);  // 파일 읽기 실패 시 할당된 페이지를 해제합니다.
			return false;
		}

		// 나머지 바이트를 0으로 채웁니다.
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* 새로 할당된 페이지를 프로세스의 주소 공간에 추가합니다. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);  // 페이지 설치 실패 시 할당된 페이지를 해제합니다.
			return false;
		}

		// 읽은 바이트와 0으로 채운 바이트를 업데이트합니다.
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;  // 다음 페이지로 넘어갑니다.
	}

	// 성공적으로 세그먼트 로드 완료
	return true;
}


/* 프로그램이 실행될 때 필요한 최소한의 스택을 설정하는 역할을 하며, 스택 포인터를 적절히 초기화하여 사용자 코드가 실행될 수 있도록 준비 */
static bool
setup_stack (struct intr_frame *if_)
{
	uint8_t *kpage;
	bool success = false;

	// 사용자 영역에서 0으로 초기화된 페이지를 할당합니다.
	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		// 할당된 페이지를 USER_STACK 위치에 매핑합니다.
		// USER_STACK은 스택의 최상단 위치를 가리키며, 페이지 크기만큼 아래로 내려갑니다.
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			// 스택 포인터를 USER_STACK으로 설정합니다. (최상단 스택 위치)
			if_->rsp = USER_STACK;
		else
			// 페이지 할당에 실패하면 할당한 페이지를 해제합니다.
			palloc_free_page (kpage);
	}
	// 페이지 할당 및 설치가 성공했으면 true를 반환하고, 실패하면 false를 반환합니다.
	return success;
}


/* 사용자 가상 주소 UPAGE를 커널 가상 주소 KPAGE에 매핑하여 페이지 테이블에 추가합니다.
 * WRITABLE이 true일 경우, 사용자는 이 페이지를 수정할 수 있으며,
 * 그렇지 않으면 읽기 전용입니다.
 * UPAGE는 이미 매핑되어 있지 않아야 합니다.
 * KPAGE는 아마도 palloc_get_page()로 사용자 풀에서 할당된 페이지일 것입니다.
 * 성공 시 true를 반환하고, UPAGE가 이미 매핑되었거나 메모리 할당에 실패한 경우 false를 반환합니다. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();  // 현재 스레드를 가져옵니다.

	/* 해당 가상 주소에 이미 페이지가 매핑되어 있지 않은지 확인한 후,
	 * 페이지를 매핑합니다. */
	return (pml4_get_page (t->pml4, upage) == NULL  // 가상 주소 UPAGE에 이미 페이지가 매핑되어 있지 않은지 확인
			&& pml4_set_page (t->pml4, upage, kpage, writable));  // 페이지 테이블에 페이지를 매핑하고, 쓰기 권한을 설정합니다.
}
#else
/* 이 부분의 코드는 프로젝트 3 이후에 사용됩니다.
 * 만약 프로젝트 2에만 필요한 기능을 구현하려면,
 * 상단의 코드 블록에서 구현하십시오. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: 파일에서 세그먼트를 로드하는 기능을 구현하십시오 */
	/* TODO: 이 함수는 주소 VA에서 첫 번째 페이지 결함(page fault)이 발생했을 때 호출됩니다. */
	/* TODO: VA는 이 함수가 호출될 때 사용할 수 있습니다. */
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
