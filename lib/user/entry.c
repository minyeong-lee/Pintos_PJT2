#include <syscall.h>

int main (int, char *[]);
void _start (int argc, char *argv[]);

/* 사용자 프로그램은 _start() 함수에서 시작한다 */
// _start()은 main()을 호출하고, main()이 종료되면 exit()을 호출하여 프로그램을 종료한다
void
_start (int argc, char *argv[]) {
	exit (main (argc, argv));  //argc는 명령줄 인자의 개수, argv는 명령줄 인자들의 배열
}
