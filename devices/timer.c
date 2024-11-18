#include "devices/timer.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include "threads/interrupt.h"
#include "threads/io.h"
#include "threads/synch.h"
#include "threads/thread.h"

/* See [8254] for hardware details of the 8254 timer chip. */

#if TIMER_FREQ < 19
#error 8254 timer requires TIMER_FREQ >= 19
#endif
#if TIMER_FREQ > 1000
#error TIMER_FREQ <= 1000 recommended
#endif

/* Number of timer ticks since OS booted. */
static int64_t ticks;

/* Number of loops per timer tick.
   Initialized by timer_calibrate(). */
static unsigned loops_per_tick;

static intr_handler_func timer_interrupt;
static bool too_many_loops (unsigned loops);
static void busy_wait (int64_t loops);
static void real_time_sleep (int64_t num, int32_t denom);

/* Sets up the 8254 Programmable Interval Timer (PIT) to
   interrupt PIT_FREQ times per second, and registers the
   corresponding interrupt. */
void
timer_init (void) {
	/* 8254 input frequency divided by TIMER_FREQ, rounded to
	   nearest. */
	uint16_t count = (1193180 + TIMER_FREQ / 2) / TIMER_FREQ;

	outb (0x43, 0x34);    /* CW: counter 0, LSB then MSB, mode 2, binary. */
	outb (0x40, count & 0xff);
	outb (0x40, count >> 8);

	intr_register_ext (0x20, timer_interrupt, "8254 Timer");
}

/* Calibrates loops_per_tick, used to implement brief delays. */
void
timer_calibrate (void) {
	unsigned high_bit, test_bit;

	ASSERT (intr_get_level () == INTR_ON);
	printf ("Calibrating timer...  ");

	/* Approximate loops_per_tick as the largest power-of-two
	   still less than one timer tick. */
	loops_per_tick = 1u << 10;
	while (!too_many_loops (loops_per_tick << 1)) {
		loops_per_tick <<= 1;
		ASSERT (loops_per_tick != 0);
	}

	/* Refine the next 8 bits of loops_per_tick. */
	high_bit = loops_per_tick;
	for (test_bit = high_bit >> 1; test_bit != high_bit >> 10; test_bit >>= 1)
		if (!too_many_loops (high_bit | test_bit))
			loops_per_tick |= test_bit;

	printf ("%'"PRIu64" loops/s.\n", (uint64_t) loops_per_tick * TIMER_FREQ);
}

//! 타이머 틱스 : OS 부팅 이후의 타이머 틱 수를 반환
int64_t
timer_ticks (void) {
	enum intr_level old_level = intr_disable ();      //* 인터럽트 OFF
	int64_t t = ticks;                    //* t = ticks 이고, t를 반환함. ticks = time_sleep 함수에서 중단하고싶은 틱 수

	intr_set_level (old_level);           //* 인터럽트 ON 
	barrier ();                           //* 컴파일러가 순서를 수정하지 못하도록함 ( 인터럽트 온오프 )
	return t;
}

/* Returns the number of timer ticks elapsed since THEN, which
   should be a value once returned by timer_ticks(). */
//! 타이머 일랩스트 : elapsed = 시간이 경과하다.
int64_t
timer_elapsed (int64_t then) {    //* then = timer_sleep이 호출된 틱 (시작 시간)
	return timer_ticks () - then;   //* timer_ticks() = 현재 틱 (현재 시간), 즉 현재 시간으로부터 경과한 시간을 리턴
}

//! 타이머 슬립 : 호출 스레드의 실행을 ticks 이 지날 때까지 중단, 실시간으로 작동하는 스레드에 유용함
void
timer_sleep (int64_t ticks) {
//*********** 의사 코드 ***********//
	// int64_t start = timer_ticks ();
  // //* ASSERT : 주어진 조건이 참이어야 함을 보장함. 거짓일 경우 ASSERT는 프로그램을 중단하고 오류 메세지를 출력
	// ASSERT (intr_get_level () == INTR_ON); //* 인터럽트가 현재 활성화 상태인지 확인
	// while (timer_elapsed (start) < ticks)  //* 경과한 시간(elapse)이 ticks 보다 짧으면, thread_yield()를 계속 호춣
	// 	thread_yield ();                      //* yield = 양보, 즉 순서를 계속 양보함
//*********** end ***********//

  ASSERT (intr_get_level () == INTR_ON);

  struct thread *now_t = thread_current (); 

  int64_t start = timer_ticks ();             
  if (timer_elapsed (start) < ticks)       // time_sleep 최초 호출틱 - timer_elapsed 호출틱이 인자의 ticks보다 짧으면
    thread_sleep (start + ticks);
}

/* Suspends execution for approximately MS milliseconds. */
void
timer_msleep (int64_t ms) {
	real_time_sleep (ms, 1000);
}

/* Suspends execution for approximately US microseconds. */
void
timer_usleep (int64_t us) {
	real_time_sleep (us, 1000 * 1000);
}

/* Suspends execution for approximately NS nanoseconds. */
void
timer_nsleep (int64_t ns) {
	real_time_sleep (ns, 1000 * 1000 * 1000);
}

/* Prints timer statistics. */
void
timer_print_stats (void) {
	printf ("Timer: %"PRId64" ticks\n", timer_ticks ());
}

/* Timer interrupt handler. */
//! 타이머 인터럽트 핸들러 : 스레드와 커널의 ticks를 매 틱마다 증가시킴
static void
timer_interrupt (struct intr_frame *args UNUSED) {
  ticks++;
	thread_tick ();

  if (thread_mlfqs) {
    if (strcmp(thread_current ()->name, "idle"))
      thread_current ()->recent_cpu += (1<<14);

    if (timer_ticks () % TIMER_FREQ == 0) {
      thread_calc_load_avg ();                      //* 전역변수인 load_avg 갱신 필요
      thread_calc_recent_cpu ();                    //* 모든 스레드의 recent_cpu 갱신 필요
    }
    
    if (timer_ticks () % 4 == 0)
      thread_calc_priority ();                      //* 모든 스레드의 우선순위 갱신
  }

  thread_wakeup (ticks);                            // ticks 마다, 스레드를 확인하여 깨울 스레드가 존재하는 지 확인
}

/* Returns true if LOOPS iterations waits for more than one timer
   tick, otherwise false. */
static bool
too_many_loops (unsigned loops) {
	/* Wait for a timer tick. */
	int64_t start = ticks;
	while (ticks == start)
		barrier ();

	/* Run LOOPS loops. */
	start = ticks;
	busy_wait (loops);

	/* If the tick count changed, we iterated too long. */
	barrier ();
	return start != ticks;
}

/* Iterates through a simple loop LOOPS times, for implementing
   brief delays.

   Marked NO_INLINE because code alignment can significantly
   affect timings, so that if this function was inlined
   differently in different places the results would be difficult
   to predict. */
static void NO_INLINE
busy_wait (int64_t loops) {
	while (loops-- > 0)
		barrier ();
}

/* Sleep for approximately NUM/DENOM seconds. */
static void
real_time_sleep (int64_t num, int32_t denom) {
	/* Convert NUM/DENOM seconds into timer ticks, rounding down.

	   (NUM / DENOM) s
	   ---------------------- = NUM * TIMER_FREQ / DENOM ticks.
	   1 s / TIMER_FREQ ticks
	   */
	int64_t ticks = num * TIMER_FREQ / denom;

	ASSERT (intr_get_level () == INTR_ON);
	if (ticks > 0) {
		/* We're waiting for at least one full timer tick.  Use
		   timer_sleep() because it will yield the CPU to other
		   processes. */
		timer_sleep (ticks);
	} else {
		/* Otherwise, use a busy-wait loop for more accurate
		   sub-tick timing.  We scale the numerator and denominator
		   down by 1000 to avoid the possibility of overflow. */
		ASSERT (denom % 1000 == 0);
		busy_wait (loops_per_tick * num / 1000 * TIMER_FREQ / (denom / 1000));
	}
}
