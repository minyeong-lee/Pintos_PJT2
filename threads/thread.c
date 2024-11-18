#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
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

static struct list ready_list;                //* 준비 완료된 스레드 리스트 : 아직 실행은 되지 않음
static struct list sleep_list;                //* 자고있는 스레드
static struct list all_list;                  //* 모든 스레드 리스트         < MLFQS >

static struct thread *idle_thread;            //* 대기 스레드 : ready_list에 준비된 스레드가 없을 때 호출되는 스레드
static struct thread *initial_thread;         //* 초기화 스레드 : init.c 의 main() 함수에서 실행됨

static struct lock tid_lock;                  //* tid 값을 가지는 스레드를 lock 함

static struct list destruction_req;           //* 스레드 파괴 요청

//! 스레드별 틱수
static long long idle_ticks;                  //* 대기 틱(idle 스레드)
static long long kernel_ticks;                //* 커널 틱(커널 스레드)
static long long user_ticks;                  //* 유저 틱(유저 프로그램 스레드)

//! 스레드별 전체 틱 및 스레드가 양보한 이후 진행된 틱
#define TIME_SLICE 4                          //* 각 스레드에게 할당된 전체 틱
static unsigned thread_ticks;                 //* 마지막으로 양보(yield)한 이후의 타이머 틱 수

//! MLFQS                        
#define F (1<<14)                             //* 고정소수점 [ p + q = (17 + 14) = 31 and F = 2 << q ]

static int load_avg;                          //* MLFQS

/*
! 멀티 레벨 피드백 큐 활성화 옵션
* false(default) : round-robin 스케쥴러
* true : multi-level feedback queue 스케쥴러
* 커널 명령줄 : -o mlfqs
*/
bool thread_mlfqs;                            


static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);

#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC) //* t가 유효한 스레드를 가리키면, true를 리턴

/* 
! 실행 중인 스레드 반환
 * CPU의 스택 포인터 'rsp'를 읽음
 * 해당 포인터를 페이지의 시작점으로 내림
 * struct thread가 항상 페이지의 시작점에 있고, 스택포인터는 중간 어딘가에 위치함
 * 따라서 항상 현재 스레드를 찾을 수 있음
*/
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */

//******************************************** 함수 ********************************************//
void print_ready() {
    enum intr_level old_level = intr_disable ();
    struct list_elem *e;
    struct thread *t;
    printf("[DEBUG] PRINTING ALL READY THREADS\n");
    for (e = list_begin(&ready_list); e != list_end(&ready_list); e = e->next) {
        t = list_entry(e, struct thread, elem);
        printf("thread#%d (%s) at %p, priority=%d\n", t->tid, t->name, e, t->priority);
        // printf("thread#%d (%s) at %p\n", t->tid, t->name, e);
    }
    printf("tail at %p\n", list_end(&ready_list));
    intr_set_level (old_level);
}

void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the globla thread context */
	lock_init (&tid_lock);
	list_init (&ready_list);
  list_init (&sleep_list);
	list_init (&destruction_req);
  list_init (&all_list);                                    //* MLFQS
  load_avg = 0;                                             //* MLFQS

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	init_thread (initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) {
	struct thread *t = thread_current ();

	/* Update statistics. */
	if (t == idle_thread)                   //* 현재 스레드가 idle_thread일 경우, idle_ticks을 증가시킴
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;                       //* idle_ticks가 아닌 경우, kernel_ticks를 증가시킴

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)       //* thread_ticks가 스레드에게 할당된 틱에 도달한 경우, 컨텍스트 스위칭 실시
		intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
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
tid_t
thread_create (const char *name, int priority,
		thread_func *function, void *aux) {
	struct thread *t;
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread (t, name, priority);

  tid = t->tid = allocate_tid ();
  if (t != idle_thread) {                                   //* MLFQS
    t->nice = thread_current ()->nice;
    t->recent_cpu = thread_current ()->recent_cpu;
    list_push_back(&all_list, &t->a_elem);
  }

#ifdef USERPROG
  /* --- Project 2 : System call --- */
  list_push_back(&thread_current ()->child_list, &t->c_elem);          //* FORK

  t->fd_table = palloc_get_multiple(PAL_ZERO, FDT_PAGES);   //* FD
  if (t->fd_table == NULL)
    return TID_ERROR;

  t->fd_idx = 2;                                            //* FD
  t->fd_table[0] = STDIN_FILENO;                            //* FD : stdin 배정 = 1
  t->fd_table[1] = STDOUT_FILENO;                           //* FD : stdout 배정 = 2
#endif

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	/* Add to run queue. */
	thread_unblock (t);
  
  if (!thread_mlfqs)
    thread_preemption ();

	return tid;
}

//! 스레드 변경
void
thread_preemption (void) {
  enum intr_level old_level;
  struct thread *curr = thread_current ();
  struct thread *ready = list_entry (list_begin (&ready_list), struct thread, elem);

  if (list_empty(&ready_list))
    return;

  old_level = intr_disable ();

  if (!intr_context() && curr->priority < ready->priority) {
    thread_yield ();
  }

  intr_set_level (old_level);
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
//! 스레드 블락(THREAD BLOCK) : 스레드를 재우고, ready_list의 다음 스레드를 실행
void
thread_block (void) {
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	thread_current ()->status = THREAD_BLOCKED;
	schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
//! 스레드 언블락(THREAD UNBLOCK) : 스레드 t를 깨우고, ready_list에 넣음
void
thread_unblock (struct thread *t) {
	enum intr_level old_level;

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);
  if (t != idle_thread)
    list_insert_ordered(&ready_list, &t->elem, cmp_priority, NULL);
	t->status = THREAD_READY;
	intr_set_level (old_level);
}

//! 스레드 재우기
void
thread_sleep (int64_t ticks) {
  enum intr_level old_level;
  struct thread *curr = thread_current ();
  curr->waken_ticks = ticks;

  ASSERT (!intr_context ());
  old_level = intr_disable();

  if (curr != idle_thread) {
    list_push_back(&sleep_list, &curr->elem);
  }
  thread_block ();
  intr_set_level (old_level);
}

//! 스레드 깨우기
void
thread_wakeup(int64_t ticks) {
  // 현재 ticks
  // sleep_list 에는 미래의 ticks가 저장되어 있음
  // if list_entry에서 값을 확인하고, 매 인터럽트마다 깨워야할 스레드가 있는지 확인해야함
  struct list_elem *e = list_begin (&sleep_list);

  while (e != list_end (&sleep_list)) {
    struct thread *chk_t = list_entry (e, struct thread, elem);
    int64_t woke_ticks = chk_t->waken_ticks;

    if (woke_ticks <= ticks) {
      e = list_remove (e);
      thread_unblock (chk_t);
    }
    else {
      e = list_next(e);
    }
  }
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	process_exit ();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	struct list_elem *e = list_head (&all_list);
  while ((e = list_next (e)) != list_end (&all_list)) {
    struct thread *t = list_entry (e, struct thread, a_elem);

    if (thread_current () == t)
      list_remove(&t->a_elem);
  }
	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
//! 스레드 양보
void
thread_yield (void) {
	struct thread *curr = thread_current ();
	enum intr_level old_level;

	ASSERT (!intr_context ());

	old_level = intr_disable ();
	if (curr != idle_thread)
    list_insert_ordered(&ready_list, &curr->elem, cmp_priority, NULL);

	do_schedule (THREAD_READY);
	intr_set_level (old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) {
	struct thread *curr = thread_current ();
  curr->origin_priority = new_priority;

  if (!thread_mlfqs) {
    if (list_empty(&curr->donations))
      curr->priority = new_priority;
    else {
      struct thread *t = list_entry (list_begin (&curr->donations), struct thread, d_elem);
      if (t->priority < new_priority)
        curr->priority = new_priority;
    }

    thread_preemption ();
  }
}

/* 
 * Returns true if A is less than B, 
 * or false if A is greater than or equal to B.
 * A가 B보다 작으면 True, a가 b보다 크거나 같으면 False
*/
//! 우선순위 비교 : list_elem에 있는 스레드들 간의 우선순위를 비교
bool 
cmp_priority (struct list_elem *a, struct list_elem *b, void *aux UNUSED) {
  struct thread *curr = list_entry (a, struct thread, elem);
  struct thread *next = list_entry (b, struct thread, elem);

  if (curr->priority > next->priority)
    return true;
  else 
    return false;
}

bool 
cmp_priority_donation (struct list_elem *a, struct list_elem *b, void *aux UNUSED) {
  struct thread *curr = list_entry (a, struct thread, d_elem);
  struct thread *next = list_entry (b, struct thread, d_elem);

  if (curr->priority > next->priority)
    return true;
  else 
    return false;
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) {
	return thread_current ()->priority;
}

void
thread_set_nice (int new_nice UNUSED) {
  struct thread *curr = thread_current ();

  curr->nice = new_nice;   
  curr->priority = ((PRI_MAX * F) - (curr->recent_cpu / 4) - (curr->nice * 2 * F))>>14;

  thread_preemption ();                                                 
}

int
thread_get_nice (void) {
	return thread_current ()->nice;
}

int
thread_get_load_avg (void) {
  //? 현재 load_avg를 100배 한 후 가장 가까운 정수로 반올림하여 반환

  int curr_load_avg = load_avg >= 0 
  ? (load_avg*100 + F/2) / F 
  : (load_avg*100 - F/2) / F;

  return curr_load_avg;
}

int
thread_get_recent_cpu (void) {
  //? 현재 스레드의 recent_cpu 값을 100배 한 후 가장 가까운 정수로 반올림하여 반환
  int curr_rcpu = thread_current ()->recent_cpu;
	
  curr_rcpu = curr_rcpu >= 0 
  ? (curr_rcpu*100 + F/2) / F 
  : (curr_rcpu*100 - F/2) / F;
  return curr_rcpu;
}

//! 전역변수 load_avg를 갱신해주는 함수
void 
thread_calc_load_avg (void) {
  int ready_threads = thread_current () == idle_thread 
  ? (int)list_size (&ready_list) 
  : (int)list_size (&ready_list) + 1;

  load_avg = (((int64_t)(59*F)/60) * load_avg)/F + ((F/60) * ready_threads);
}

//! 모든 스레드의 recent_cpu를 갱신해주는 함수
void
thread_calc_recent_cpu (void) {
  struct list_elem *e = list_head (&all_list);

  while ((e = list_next (e)) != list_end (&all_list)) {
    struct thread *t = list_entry (e, struct thread, a_elem);
    t->recent_cpu = (int64_t)t->recent_cpu * (2 * load_avg) / (2 * load_avg + F) + (t->nice * F);
  }
}

//! 모든 스레드의 priority를 갱신해주는 함수
void
thread_calc_priority (void) {
  struct list_elem *e = list_head (&all_list);

  while ((e = list_next (e)) != list_end (&all_list)) {
    struct thread *t = list_entry (e, struct thread, a_elem);
    t->priority = ((PRI_MAX * F) - (t->recent_cpu / 4) - (t->nice * 2 * F))>>14;
  }
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
  list_remove (&idle_thread->a_elem);                       //* MLFQS
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

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
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority) {
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);

	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);
	t->priority = priority;
  t->origin_priority = priority;
	t->magic = THREAD_MAGIC;
  list_init (&t->donations);
  t->recent_cpu = 0;                                        //* MLFQS
  t->nice = 0;                                              //* MLFQS

#ifdef USERPROG
  list_init (&t->child_list);
  sema_init(&t->wait_sema, 0);
  sema_init(&t->load_sema, 0);
  sema_init(&t->exit_sema, 0);
#endif
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list))
		return idle_thread;
	else
		return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n"
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
//! 강제로 현재 스레드를 인자(status) 상태로 만들고, ready_list에서 다음 스레드 실행
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	while (!list_empty (&destruction_req)) {
		struct thread *victim =
			list_entry (list_pop_front (&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current ()->status = status;
	schedule ();
}

//! 현재 스레드의 상태가 RUNNING이 아니면, 다음 스레드를 running으로 만듦
static void
schedule (void) {
	struct thread *curr = running_thread ();
	struct thread *next = next_thread_to_run ();

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);
	ASSERT (is_thread (next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used by the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			list_push_back (&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch (next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}
