#include "threads/thread.h"

#include <debug.h>
#include <random.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "intrinsic.h"
#include "threads/fixed_point.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/** #Project 1: Alarm Clock 전역 변수 */
static struct list sleep_list;
static int64_t next_tick_to_awake;

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/** #Project 1: Advanced Scheduler */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;   /* # of timer ticks spent idle. */
static long long kernel_ticks; /* # of timer ticks in kernel threads. */
static long long user_ticks;   /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4          /* # of timer ticks to give each thread. */
static unsigned thread_ticks; /* # of timer ticks since last yield. */

/** #Project 1: Advanced Scheduler */
int load_avg;

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread(thread_func *, void *aux);

static void idle(void *aux UNUSED);
static struct thread *next_thread_to_run(void);
static void init_thread(struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule(void);
static tid_t allocate_tid(void);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *)(pg_round_down(rrsp())))

// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = {0, 0x00af9a000000ffff, 0x00cf92000000ffff};

/* 현재 실행 중인 코드를 스레드로 변환하여 스레딩 시스템을 초기화합니다.
   이것은 일반적으로 작동하지 않으며 이 경우에만 가능합니다. 왜냐하면 loader.S가
   스택의 맨 아래를 페이지 경계에 두는 데 주의를 기울였기 때문입니다.

   또한 실행 큐와 tid 잠금을 초기화합니다..

   이 함수를 호출한 후 thread_create()를 사용하여 스레드를 생성하기 전에
   page allocator를 초기화해야 합니다.

   이 함수가 완료될 때까지 thread_current()를 호출하는 것은 안전하지 않습니다.*/
void thread_init(void) {
    ASSERT(intr_get_level() == INTR_OFF);

    /* Reload the temporal gdt for the kernel
     * This gdt does not include the user context.
     * The kernel will rebuild the gdt with user context, in gdt_init (). */
    struct desc_ptr gdt_ds = {.size = sizeof(gdt) - 1, .address = (uint64_t)gdt};
    lgdt(&gdt_ds);

    /* Init the globla thread context */
    lock_init(&tid_lock);
    list_init(&ready_list);
    list_init(&destruction_req);

    /** #Project 1: Alarm Clock sleep list 초기화 */
    list_init(&sleep_list);

    /** #Project 1: Advanced Scheduler all list 초기화 */
    list_init(&all_list);

    /* Set up a thread structure for the running thread. */
    initial_thread = running_thread();
    init_thread(initial_thread, "main", PRI_DEFAULT);

    initial_thread->status = THREAD_RUNNING;
    initial_thread->tid = allocate_tid();
}

/* 인터럽트를 활성화하여 선점형 스레드 스케줄링을 시작합니다.
   또한 idle 스레드를 생성합니다. */
void thread_start(void) {
    /* Create the idle thread. */
    struct semaphore idle_started;
    sema_init(&idle_started, 0);
    thread_create("idle", PRI_MIN, idle, &idle_started);

    /** #Project 1: Advanced Scheduler */
    load_avg = LOAD_AVG_DEFAULT;

    /* 선점형 스레드 스케줄링 시작. */
    intr_enable();

    /* 유휴 스레드가 유휴 스레드를 초기화할 때까지 기다립니다. */
    sema_down(&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void thread_tick(void) {
    struct thread *t = thread_current();

    /* Update statistics. */
    if (t == idle_thread)
        idle_ticks++;
#ifdef USERPROG
    else if (t->pml4 != NULL)
        user_ticks++;
#endif
    else
        kernel_ticks++;

    /* Enforce preemption. */
    if (++thread_ticks >= TIME_SLICE)
        intr_yield_on_return();
}

/* Prints thread statistics. */
void thread_print_stats(void) {
    printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n", idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t thread_create(const char *name, int priority, thread_func *function, void *aux) {
    struct thread *t;
    tid_t tid;

    ASSERT(function != NULL);

    /* Allocate thread. */
    t = palloc_get_page(PAL_ZERO);
    if (t == NULL)
        return TID_ERROR;

    /* Initialize thread. */
    init_thread(t, name, priority);
    tid = t->tid = allocate_tid();
#ifdef USERPROG
    /** #Project 2: System Call - 구조체 초기화 */
    t->fdt = palloc_get_multiple(PAL_ZERO, FDT_PAGES);
    if (t->fdt == NULL)
        return TID_ERROR;

    t->exit_status = 0;  // exit_status 초기화

    t->fd_idx = 3;
    t->fdt[0] = STDIN;  // stdin 예약된 자리 (dummy)
    t->fdt[1] = STDOUT;  // stdout 예약된 자리 (dummy)
    t->fdt[2] = STDERR;  // stderr 예약된 자리 (dummy)
    /** ---------------------------------------- */
    /** #Project 2: Extend File Descriptor (Extra) 구조체 초기화 */
    t->stdin_count = 1;
    t->stdout_count = 1;
    t->stderr_count = 1;
    /** ------------------------------------------------------- */ 

    /** #Project 2: System Call - 현재 스레드의 자식 리스트에 추가 */
    list_push_back(&thread_current()->child_list, &t->child_elem);
#endif
    /* Call the kernel_thread if it scheduled.
     * Note) rdi is 1st argument, and rsi is 2nd argument. */
    t->tf.rip = (uintptr_t)kernel_thread;
    t->tf.R.rdi = (uint64_t)function;
    t->tf.R.rsi = (uint64_t)aux;
    t->tf.ds = SEL_KDSEG;
    t->tf.es = SEL_KDSEG;
    t->tf.ss = SEL_KDSEG;
    t->tf.cs = SEL_KCSEG;
    t->tf.eflags = FLAG_IF;

    /* Add to run queue. */
    thread_unblock(t);

    /** #Project 1: Priority Scheduling 새로 생성된 thread의 우선순위가 더 높다면 cpu 인계 */
    if (t->priority > thread_get_priority())
        thread_yield();

    return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void thread_block(void) {
    ASSERT(!intr_context());
    ASSERT(intr_get_level() == INTR_OFF);
    thread_current()->status = THREAD_BLOCKED;
    schedule();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void thread_unblock(struct thread *t) {
    enum intr_level old_level;

    ASSERT(is_thread(t));

    old_level = intr_disable();
    ASSERT(t->status == THREAD_BLOCKED);

    /** #Project 1: Priority Scheduling 우선순위 순으로 정렬되어 list에 삽입 */
    list_insert_ordered(&ready_list, &t->elem, cmp_priority, NULL);
    // list_push_back(&ready_list, &t->elem);
    t->status = THREAD_READY;
    intr_set_level(old_level);
}

/* Returns the name of the running thread. */
const char *thread_name(void) {
    return thread_current()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *thread_current(void) {
    struct thread *t = running_thread();

    /* Make sure T is really a thread.
       If either of these assertions fire, then your thread may
       have overflowed its stack.  Each thread has less than 4 kB
       of stack, so a few big automatic arrays or moderate
       recursion can cause stack overflow. */
    ASSERT(is_thread(t));
    ASSERT(t->status == THREAD_RUNNING);

    return t;
}

/* Returns the running thread's tid. */
tid_t thread_tid(void) {
    return thread_current()->tid;
}

/* 현재 스레드의 일정을 취소하고 삭제. 절대 재귀적으로 호출되지 않음. */
void thread_exit(void) {
    ASSERT(!intr_context());

#ifdef USERPROG
    process_exit();
#endif
    /** #Project 1: Advanced Scheduler 스레드 종료 시 all_list에서 제거 */
    if (thread_mlfqs)
        list_remove(&thread_current()->all_elem);

    /* 상태를 죽어가는 것으로 설정하고 다른 프로세스를 예약
       이 쓰레드는 Schedule_tail()을 호출하는 동안 파괴됨 */
    intr_disable();
    do_schedule(THREAD_DYING);
    NOT_REACHED();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void thread_yield(void) {
    struct thread *curr = thread_current();
    enum intr_level old_level;

    ASSERT(!intr_context());

    old_level = intr_disable();
    if (curr != idle_thread)
        /** #Project 1: Priority Scheduling 우선순위 순으로 정렬되어 list에 삽입 */
        list_insert_ordered(&ready_list, &curr->elem, cmp_priority, NULL);
    // list_push_back(&ready_list, &curr->elem);
    do_schedule(THREAD_READY);
    intr_set_level(old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void thread_set_priority(int new_priority) {
    /** #Project 1: Advanced Scheduler mlfqs 스케줄러 일때 우선순위를 임의로 변경할수 없도록 수정 */
    if (thread_mlfqs)
        return;

    /** #Project 1: Priority Donation */
    thread_current()->original_priority = new_priority;  // prioirity 대신 original priority 사용

    refresh_priority();  // donation 관련 정보 갱신 및 스케줄링
    /** ----------------------------- */

    /** #Project 1: Priority Scheduling 우선순위를 비교하여 스케쥴링 하는 함수 호출 */
    test_max_priority();
}

/* Returns the current thread's priority. */
int thread_get_priority(void) {
    return thread_current()->priority;
}

/** #Project 1: Advanced Scheduler 현재 thread의 niceness값을 변경하는 함수 */
void thread_set_nice(int nice UNUSED) {
    thread_t *t = thread_current();

    enum intr_level old_level = intr_disable();
    t->niceness = nice;
    mlfqs_priority(t);
    test_max_priority();
    intr_set_level(old_level);
}

/** #Project 1: Advanced Scheduler 현재 thread의 niceness값을 반환하는 함수 */
int thread_get_nice(void) {
    thread_t *t = thread_current();

    enum intr_level old_level = intr_disable();
    int nice = t->niceness;
    intr_set_level(old_level);

    return nice;
}

/** #Project 1: Advanced Scheduler load_avg에 100을 곱해서 반환하는 함수 */
int thread_get_load_avg(void) {
    enum intr_level old_level = intr_disable();
    int load_avg_val = fp_to_int_round(mult_mixed(load_avg, 100));  // 출력시 소수 2번째 자리까지 출력하기 위함
    intr_set_level(old_level);

    return load_avg_val;
}

/* Returns 100 times the current thread's recent_cpu value. */
int thread_get_recent_cpu(void) {
    thread_t *t = thread_current();

    enum intr_level old_level = intr_disable();
    int recent_cpu = fp_to_int_round(mult_mixed(t->recent_cpu, 100));  // 출력시 소수 2번째 자리까지 출력하기 위함
    intr_set_level(old_level);

    return recent_cpu;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void idle(void *idle_started_ UNUSED) {
    struct semaphore *idle_started = idle_started_;

    idle_thread = thread_current();
    sema_up(idle_started);

    for (;;) {
        /* Let someone else run. */
        intr_disable();
        thread_block();

        /* Re-enable interrupts and wait for the next one.

           The `sti' instruction disables interrupts until the
           completion of the next instruction, so these two
           instructions are executed atomically.  This atomicity is
           important; otherwise, an interrupt could be handled
           between re-enabling interrupts and waiting for the next
           one to occur, wasting as much as one clock tick worth of
           time.

           See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
           7.11.1 "HLT Instruction". */
        asm volatile("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void kernel_thread(thread_func *function, void *aux) {
    ASSERT(function != NULL);

    intr_enable(); /* The scheduler runs with interrupts off. */
    function(aux); /* Execute the thread function. */
    thread_exit(); /* If function() returns, kill the thread. */
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void init_thread(struct thread *t, const char *name, int priority) {
    ASSERT(t != NULL);
    ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
    ASSERT(name != NULL);

    memset(t, 0, sizeof *t);
    t->status = THREAD_BLOCKED;
    strlcpy(t->name, name, sizeof t->name);
    t->tf.rsp = (uint64_t)t + PGSIZE - sizeof(void *);

    if (thread_mlfqs) {
        /** #Project 1: Advanced Scheduler 자료구조 초기화 */
        mlfqs_priority(t);
        list_push_back(&all_list, &t->all_elem);
    } else {
        /** #Project 1: Priority Donation 자료구조 초기화 */
        t->priority = priority;
    }

    t->wait_lock = NULL;
    list_init(&t->donations);

    t->magic = THREAD_MAGIC;

    /** #Project 1: Advanced Scheduler */
    t->original_priority = t->priority;
    t->niceness = NICE_DEFAULT;
    t->recent_cpu = RECENT_CPU_DEFAULT;

#ifdef USERPROG
    /** #Project 2: System Call  */
    t->runn_file = NULL;

    list_init(&t->child_list);
    sema_init(&t->fork_sema, 0);
    sema_init(&t->exit_sema, 0);
    sema_init(&t->wait_sema, 0);
    /** -----------------------  */
#endif
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *next_thread_to_run(void) {
    if (list_empty(&ready_list))
        return idle_thread;
    else
        return list_entry(list_pop_front(&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread *** 실제로 context switching을 하는 함수 *** */
void do_iret(struct intr_frame *tf) {
    /* Structure -> CPU Register로 데이터 이동 (Load) */
    __asm __volatile(             // 입력한 그대로 사용
        "movq %0, %%rsp\n"        // 인자 *tf의 주소를 Register Stack Pointer RSP에 저장
        "movq 0(%%rsp),%%r15\n"   // rsp위치의 값(stack 시작)을 레지스터 r15에 저장
        "movq 8(%%rsp),%%r14\n"   // rsp+8위치의 값을 레지스터 r14에 저장
        "movq 16(%%rsp),%%r13\n"  // rsp+16위치의 값을 레지스터 r16에 저장
        "movq 24(%%rsp),%%r12\n"  // rsp+24 위치의 값을 레지스터 r12에 저장
        "movq 32(%%rsp),%%r11\n"
        "movq 40(%%rsp),%%r10\n"
        "movq 48(%%rsp),%%r9\n"
        "movq 56(%%rsp),%%r8\n"
        "movq 64(%%rsp),%%rsi\n"  // ...
        "movq 72(%%rsp),%%rdi\n"
        "movq 80(%%rsp),%%rbp\n"
        "movq 88(%%rsp),%%rdx\n"
        "movq 96(%%rsp),%%rcx\n"   // rsp+96 위치의 값을 레지스터 rcx에 저장
        "movq 104(%%rsp),%%rbx\n"  // rsp+104 위치의 값을 레지스터 rbx에 저장
        "movq 112(%%rsp),%%rax\n"  // rsp+112 위치의 값을 레지스터 rax에 저장

        "addq $120,%%rsp\n"     // rsp 위치를 정수 레지스터 다음으로 이동-> rsp->es
        "movw 8(%%rsp),%%ds\n"  // rsp+8위치의 값을 레지스터 ds(data segment)에 저장
        "movw (%%rsp),%%es\n"   // rsp 위치의 값을 레지스터 es(extra segment)에 저장

        "addq $32, %%rsp\n"  // rsp 위치를 rsp+32로 이동. rsp->rip
        "iretq"              // rip 이하(cs, eflags, rsp, ss) 인터럽트 프레임에서 CPU로 복원. (직접 ACCESS 불가능)
        :                    // 인터럽트 프레임의 rip 값을 복원함으로서 기존에 수행하던 스레드의 다음 명령 실행 ... ?
        : "g"((uint64_t)tf)  // g=인자. 0번 인자로 tf를 받음
        : "memory");
}

/* 새 스레드의 페이지 테이블을 활성화하여 스레드를 전환하고, 이전 스레드가 죽어 있으면 이를 삭제합니다.

   이 함수를 호출할 때 방금 PREV 스레드에서 전환했으며 새 스레드가 이미 실행 중이고 인터럽트는 여전히
   비활성화되어 있습니다.

   스레드 전환이 완료될 때까지 printf()를 호출하는 것은 안전하지 않습니다. 실제로 이는 printf()를 함수
   끝에 추가해야 함을 의미합니다. */
static void thread_launch(struct thread *th) {
    uint64_t tf_cur = (uint64_t)&running_thread()->tf;
    uint64_t tf = (uint64_t)&th->tf;
    ASSERT(intr_get_level() == INTR_OFF);

    /* 주요 스위칭 로직.
     * 먼저 전체 실행 컨텍스트를 intr_frame으로 복원한 후 do_iret를 호출하여 다음 스레드로 전환합니다.
     * 전환이 완료될 때까지 여기에서 스택을 사용해서는 안 됩니다.*/
    __asm __volatile(
        /* 레지스터 정보를 Stack에 임시로 저장. */
        "push %%rax\n"  // Stack에 rax위치의 값 저장
        "push %%rbx\n"  // Stack에 rbx위치의 값 저장
        "push %%rcx\n"  // Stack에 rcs위치의 값 저장

        /* 현재 CPU Register -> Structure 로 데이터 이동 (Backup) */
        "movq %0, %%rax\n"          // 0번 인자의 주소를 레지스터 rax에 저장
        "movq %1, %%rcx\n"          // 1번 인자의 주소를 레지스터 rcx에 저장
        "movq %%r15, 0(%%rax)\n"    // 레지스터 r15의 값을 rax+0 위치에 저장
        "movq %%r14, 8(%%rax)\n"    // 레지스터 r14의 값을 rax+8 위치에 저장
        "movq %%r13, 16(%%rax)\n"   // 레지스터 r13의 값을 rax+16 위치에 저장
        "movq %%r12, 24(%%rax)\n"   // 레지스터 r12의 값을 rax+24 위치에 저장
        "movq %%r11, 32(%%rax)\n"   // 레지스터 r11의 값을 rax+32 위치에 저장
        "movq %%r10, 40(%%rax)\n"   // 레지스터 r10의 값을 rax+40 위치에 저장
        "movq %%r9, 48(%%rax)\n"    // 레지스터 r9의 값을 rax+48 위치에 저장
        "movq %%r8, 56(%%rax)\n"    // 레지스터 r8의 값을 rax+56 위치에 저장
        "movq %%rsi, 64(%%rax)\n"   // 레지스터 rsi의 값을 rax+64 위치에 저장
        "movq %%rdi, 72(%%rax)\n"   // 레지스터 rdi의 값을 rax+72 위치에 저장
        "movq %%rbp, 80(%%rax)\n"   // 레지스터 rbp의 값을 rax+80 위치에 저장
        "movq %%rdx, 88(%%rax)\n"   // 레지스터 rdx의 값을 rax+88 위치에 저장
        "pop %%rbx\n"               // Stack에 저장된 rcx의 값을 rbx 위치에 복원
        "movq %%rbx, 96(%%rax)\n"   // 레지스터 rbx의 값을 rax+96 위치에 저장
        "pop %%rbx\n"               // Stack에 저장된 rbx의 값을 rbx 위치에 복원
        "movq %%rbx, 104(%%rax)\n"  // 레지스터 rbx의 값을 rax+104 위치에 저장
        "pop %%rbx\n"               // Stack에 저장된 rax의 값을 rbx 위치에 복원
        "movq %%rbx, 112(%%rax)\n"  // 레지스터 rbx의 값을 rax+112 위치에 저장
        "addq $120, %%rax\n"        // 레지스터 rax의 위치를 정수 레지스터 다음으로 이동 rax->es
        "movw %%es, (%%rax)\n"      // es값을 rax의 위치(es)에 저장
        "movw %%ds, 8(%%rax)\n"     // ds값을 rax+8의 위치(ds)에 저장
        "addq $32, %%rax\n"         // 레지스터 rax를 rip 위치로 이동

        "call __next\n"  // "__next"로 레이블된 위치를 스택에 콜

        "__next:\n"  // "__next" 레이블: 다음으로 이동할 레이블

        "pop %%rbx\n"                          // Stack에 저장한 위치를 rbx에 복원
        "addq $(out_iret -  __next), %%rbx\n"  // rbx의 위치를 (out_iret - __next를 미리계산)의 값으로 이동한다 -> 다시 이 스레드를 실행 시 out_iret부터 재개
        "movq %%rbx, 0(%%rax)\n"               // rbx의 위치를 rax+0(rip)에 저장
        "movw %%cs, 8(%%rax)\n"                // 레지스터 cs의 값을 rax+8(cs)에 저장

        "pushfq\n"                // 현재의 플래그 레지스터 내용을 Stack에 저장 (직접 ACCESS 불가)
        "popq %%rbx\n"            // Stack에 저장한 내용을 rbx에 복원
        "mov %%rbx, 16(%%rax)\n"  // 레지스터 rbx(eflags)의 값을 rax+16(eflags)에 저장
        "mov %%rsp, 24(%%rax)\n"  // 레지스터 rsp의 값을 rax+24(rsp)에 저장
        "movw %%ss, 32(%%rax)\n"  // 레지스터 ss의 값을 rax+32(rax)에 저장

        "mov %%rcx, %%rdi\n"  // 레지스터 rcx의 값(인자 1번 tf의 주소)을 레지스터 레지스터 rdi로 복사
        "call do_iret\n"      // rdi를 인자로 받아 do_iret 함수 호출

        "out_iret:\n"           // "out_iret" 레이블: 다음으로 이동할 레이블
        :                       // output operands
        : "g"(tf_cur), "g"(tf)  // input operands
        : "memory");            // list of clobbered registers -> memory의 register들이 asm 실행 전/후 갱신되어야 함
}

/* 새로운 프로세스를 예약합니다. 진입 시 인터럽트는 꺼져 있어야 합니다.
 * 이 함수는 현재 스레드의 상태를 status로 수정한 다음
 * 실행할 다른 스레드를 찾아서 전환합니다.
 * Schedule()에서 printf()를 호출하는 것은 안전하지 않습니다. */
static void do_schedule(int status) {
    ASSERT(intr_get_level() == INTR_OFF);
    ASSERT(thread_current()->status == THREAD_RUNNING);
    while (!list_empty(&destruction_req)) {
        struct thread *victim = list_entry(list_pop_front(&destruction_req), struct thread, elem);
        palloc_free_page(victim);
    }
    thread_current()->status = status;
    schedule();
}

static void schedule(void) {
    struct thread *curr = running_thread();
    struct thread *next = next_thread_to_run();

    ASSERT(intr_get_level() == INTR_OFF);
    ASSERT(curr->status != THREAD_RUNNING);
    ASSERT(is_thread(next));
    /* Mark us as running. */
    next->status = THREAD_RUNNING;

    /* Start new time slice. */
    thread_ticks = 0;

#ifdef USERPROG
    /* Activate the new address space. */
    process_activate(next);
#endif

    if (curr != next) {
        /* 전환한 스레드가 죽어가고 있으면 해당 스레드의 구조체 스레드를 삭제합니다.
           thread_exit()가 자체 아래 바닥을 호출하지 않도록 이 작업은 늦게 발생해야
           합니다.
           페이지가 현재 스택에서 사용되고 있기 때문에 여기서는 페이지 사용 가능 요청
           을 대기열에 추가합니다.
           실제 소멸 로직은 Schedule() 시작 부분에서 호출됩니다. */
        if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
            ASSERT(curr != next);
            list_push_back(&destruction_req, &curr->elem);
        }

        /* Before switching the thread, we first save the information
         * of current running. */
        thread_launch(next);
    }
}

/* Returns a tid to use for a new thread. */
static tid_t allocate_tid(void) {
    static tid_t next_tid = 1;
    tid_t tid;

    lock_acquire(&tid_lock);
    tid = next_tid++;
    lock_release(&tid_lock);

    return tid;
}

/** #Project 1: Alarm Clock 쓰레드 비활성화 함수 */
void thread_sleep(int64_t ticks) {
    thread_t *curr = thread_current();

    if (curr == idle_thread) {  // idle -> stop
        ASSERT(0);
    } else {
        enum intr_level old_level;
        old_level = intr_disable();  // pause interrupt

        update_next_tick_to_awake(curr->wakeup_tick = ticks);  // update awake ticks

        list_push_back(&sleep_list, &curr->elem);  // push to sleep_list

        thread_block();  // block this thread

        intr_set_level(old_level);  // continue interrupt
    }
}
/** #Project 1: Alarm Clock 쓰레드 활성화 함수 */
void thread_awake(int64_t wakeup_tick) {
    next_tick_to_awake = INT64_MAX;

    struct list_elem *sleeping = list_begin(&sleep_list);  // take sleeping thread
    thread_t *th;

    while (sleeping != list_end(&sleep_list)) {  // for all sleeping threads
        th = list_entry(sleeping, thread_t, elem);

        if (wakeup_tick >= th->wakeup_tick) {
            sleeping = list_remove(&th->elem);  // delete thread
            thread_unblock(th);                 // unblock thread
        } else {
            update_next_tick_to_awake(th->wakeup_tick);  // update wakeup_tick
            sleeping = list_next(sleeping);              // move to next sleeping thread
        }
    }
}

/** #Project 1: Alarm Clock 다음 활성화 tick 갱신 함수 */
void update_next_tick_to_awake(int64_t ticks) {
    next_tick_to_awake = (next_tick_to_awake > ticks) ? ticks : next_tick_to_awake;
}

/** #Project 1: Alarm Clock 현재 next_tick_to_awake 값 리턴 함수 */
int64_t get_next_tick_to_awake(void) {
    return next_tick_to_awake;
}

/** #Project 1: Priority Scheduling ready_list에서 우선 순위가 가장 높은 쓰레드와 현재 쓰레드의 우선 순위를 비교 */
void test_max_priority(void) {
    if (list_empty(&ready_list))
        return;

    thread_t *th = list_entry(list_front(&ready_list), thread_t, elem);

    if (thread_current()->priority < th->priority) {
        /** Project 2: Panic 방지 */
        if (intr_context())
            intr_yield_on_return();
        else
            thread_yield();
    }
}

/** #Project 1: Priority Scheduling 첫번째 인자의 우선순위가 높으면 1, 아니면 0 */
bool cmp_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED) {
    thread_t *thread_a = list_entry(a, thread_t, elem);
    thread_t *thread_b = list_entry(b, thread_t, elem);

    if (thread_a == NULL || thread_b == NULL)
        return false;

    return thread_a->priority > thread_b->priority;
}

/** #Project 1: Priority Donation 현재 쓰레드가 기다리고 있는 lock과 연결된 모든 쓰레드들을 순회하며
 *  현재 쓰레드의 우선순위를 lock을 보유하고 있는 쓰레드에게 기부한다. */
void donate_priority() {
    thread_t *t = thread_current();
    int priority = t->priority;

    for (int depth = 0; depth < 8; depth++) {
        if (t->wait_lock == NULL)
            break;

        t = t->wait_lock->holder;
        t->priority = priority;
    }
}

/** #Project 1: Priority Donation 현재 쓰레드의 waiters 리스트를 확인하여 해지할 lock을 보유하고 있는
 *  엔트리를 삭제한다. */
void remove_with_lock(struct lock *lock) {
    thread_t *t = thread_current();
    struct list_elem *curr = list_begin(&t->donations);
    thread_t *curr_thread = NULL;

    while (curr != list_end(&t->donations)) {
        curr_thread = list_entry(curr, thread_t, donation_elem);

        if (curr_thread->wait_lock == lock)
            list_remove(&curr_thread->donation_elem);

        curr = list_next(curr);
    }
}

/** #Project 1: Priority Donation 쓰레드의 우선순위가 변경되었을 때, donation을 고려하여 우선순위를
 *  다시 결정하는 함수 */
void refresh_priority(void) {
    /* 현재 쓰레드의 우선순위를 기부 받기 전의 우선순위로 변경.
    현재 쓰레드의 waiters 리스트에서 가장 높은 우선순위를 현재 쓰레드의 우선순위와 비교 후 우선순위 결정 */
    thread_t *t = thread_current();
    t->priority = t->original_priority;

    if (list_empty(&t->donations))
        return;

    list_sort(&t->donations, cmp_priority, NULL);

    struct list_elem *max_elem = list_front(&t->donations);
    thread_t *max_thread = list_entry(max_elem, thread_t, donation_elem);

    if (t->priority < max_thread->priority)
        t->priority = max_thread->priority;
}

/** #Project 1: Advanced Scheduler MLFQS Priority 계산하는 함수*/
void mlfqs_priority(struct thread *t) {
    if (t == idle_thread)
        return;

    t->priority = fp_to_int(add_mixed(div_mixed(t->recent_cpu, -4), PRI_MAX - t->niceness * 2));
}

/** #Project 1: Advanced Scheduler MLFQS Recent Cpu 계산하는 함수 */
void mlfqs_recent_cpu(struct thread *t) {
    if (t == idle_thread)
        return;

    t->recent_cpu = add_mixed(mult_fp(div_fp(mult_mixed(load_avg, 2), add_mixed(mult_mixed(load_avg, 2), 1)), t->recent_cpu), t->niceness);
}

/** #Project 1: Advanced Scheduler MLFQS Load Average 계산하는 함수 */
void mlfqs_load_avg(void) {
    int ready_threads;

    ready_threads = list_size(&ready_list);

    if (thread_current() != idle_thread)
        ready_threads++;

    load_avg = add_fp(mult_fp(div_fp(int_to_fp(59), int_to_fp(60)), load_avg), mult_mixed(div_fp(int_to_fp(1), int_to_fp(60)), ready_threads));
}

/** #Project 1: Advanced Scheduler MLFQS Recent CPU에 1을 더하는 함수 */
void mlfqs_increment(void) {
    if (thread_current() == idle_thread)
        return;

    thread_current()->recent_cpu = add_mixed(thread_current()->recent_cpu, 1);
}

/** #Project 1: Advanced Scheduler MLFQS 모든 Recent CPU 재계산 */
void mlfqs_recalc_recent_cpu(void) {
    struct list_elem *e = list_begin(&all_list);
    thread_t *t = NULL;

    while (e != list_end(&all_list)) {
        t = list_entry(e, thread_t, all_elem);
        mlfqs_recent_cpu(t);

        e = list_next(e);
    }
}

/** #Project 1: Advanced Scheduler MLFQS 모든 Priority 재계산 */
void mlfqs_recalc_priority(void) {
    struct list_elem *e = list_begin(&all_list);
    thread_t *t = NULL;

    while (e != list_end(&all_list)) {
        t = list_entry(e, thread_t, all_elem);
        mlfqs_priority(t);

        e = list_next(e);
    }
}
