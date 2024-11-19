#include "filesys/file.h"
#include <debug.h>
#include "filesys/inode.h"
#include "threads/malloc.h"

/* 파일 시스템에서 열린 파일을 나타내는 구조체 */
struct file
{
    struct inode *inode;        /* 파일의 inode에 대한 포인터로, 파일 메타데이터를 포함하며
                                   실제 파일 데이터의 저장을 관리합니다. 같은 파일을 참조하는 
                                   여러 파일 디스크립터가 이 inode를 공유할 수 있습니다. */
    
    off_t pos;                  /* 파일 내 현재 위치(offset)를 나타내며, 다음 읽기 또는 쓰기 
                                   작업이 시작될 위치를 의미합니다. file_seek()을 사용하여 
                                   위치를 조정할 수 있어 임의 접근이 가능합니다. */
    
    bool deny_write;            /* 이 파일에 대한 쓰기 작업을 금지할지를 나타내는 플래그입니다.
                                   file_deny_write()가 호출되면 true로 설정되어 쓰기 작업이
                                   금지되며, 다른 프로세스와의 쓰기 충돌을 방지할 수 있습니다. */
};


/* 주어진 INODE를 기반으로 파일을 열고, 새로운 파일 구조체를 반환합니다.
 * 이 함수는 INODE의 소유권을 가져오며, 파일을 나타내는 새 구조체 포인터를 반환합니다.
 * 만약 메모리 할당에 실패하거나 INODE가 null이면, null 포인터를 반환합니다. */
struct file *file_open (struct inode *inode)
{
    /* 파일 구조체를 위한 메모리를 할당하고 초기화합니다. */
    struct file *file = calloc(1, sizeof *file);

    /* INODE와 FILE이 유효한 경우 파일 구조체를 초기화합니다. */
    if (inode != NULL && file != NULL) {
        file->inode = inode;          		/* 파일의 inode 설정 */
        file->pos = 0;                		/* 파일의 현재 위치를 시작 위치로 설정 (0) */
        file->deny_write = false;     		/* 기본적으로 쓰기 허용 상태로 설정 */
        return file;                  		/* 초기화된 파일 구조체 반환 */
    } else {
        /* 할당 실패 또는 INODE가 NULL인 경우 정리 후 NULL 반환 */
        inode_close(inode);           		/* INODE 자원을 해제 */
        free(file);                   		/* 파일 구조체 메모리 해제 */
        return NULL;                  		/* 실패를 나타내기 위해 NULL 반환 */
    }
}


/* FILE과 동일한 inode를 사용하는 새 파일을 열고 반환합니다.
 * 열기에 실패하면 null 포인터를 반환합니다. */
struct file *file_reopen (struct file *file)
{
    /* FILE의 inode를 다시 열고, 이를 기반으로 새 파일을 생성하여 반환합니다. */
    return file_open(inode_reopen(file->inode));
}


/* FILE과 동일한 inode와 속성을 가진 파일 객체를 복제하고,
 * 새 파일 구조체를 반환합니다. 실패 시 null 포인터를 반환합니다. */
struct file *file_duplicate (struct file *file)
{
    /* FILE의 inode를 기반으로 새 파일을 생성 */
    struct file *nfile = file_open(inode_reopen(file->inode));
    
    if (nfile) {  				  /* 파일 생성에 성공한 경우 */
        nfile->pos = file->pos;   /* 복제된 파일의 위치를 원본 파일 위치로 설정 */
        
        /* 원본 파일이 쓰기 금지 상태라면 복제된 파일에도 쓰기 금지 설정 */
        if (file->deny_write)
            file_deny_write(nfile);
    }
    
    /* 복제된 파일 객체를 반환 (실패 시 NULL 반환) */
    return nfile;
}


/* FILE을 닫습니다. */
void file_close(struct file *file)
{
    if (file != NULL) {                // FILE이 NULL이 아닐 경우에만 수행
        file_allow_write(file);        // 쓰기 금지 플래그를 해제하여 다른 쓰기 작업이 가능하도록 설정
        inode_close(file->inode);      // FILE이 참조하는 inode를 닫아 inode 자원을 해제
        free(file);                    // FILE 구조체에 할당된 메모리를 해제
    }
}


/* FILE이 포함하고 있는 inode를 반환합니다. */
struct inode *file_get_inode(struct file *file)
{
    return file->inode;
}


/* FILE에서 SIZE 바이트를 BUFFER로 읽어옵니다.
 * 파일의 현재 위치에서부터 시작하며,
 * 파일 끝에 도달할 경우 SIZE보다 적은 바이트를 읽을 수 있습니다.
 * 읽은 바이트 수만큼 FILE의 현재 위치를 이동시킵니다.
 * 실제로 읽은 바이트 수를 반환합니다. */
off_t file_read(struct file *file, void *buffer, off_t size)
{
    off_t bytes_read = inode_read_at(file->inode, buffer, size, file->pos); // 현재 위치에서 SIZE 바이트를 읽음
    file->pos += bytes_read;  												// 읽은 바이트 수만큼 파일의 위치를 이동시킴
    return bytes_read;        												// 실제로 읽은 바이트 수 반환
}


/* FILE에서 FILE_OFS 위치부터 시작하여 SIZE 바이트를 BUFFER로 읽어옵니다.
 * 파일의 끝에 도달하면 SIZE보다 적은 바이트를 읽을 수 있습니다.
 * 파일의 현재 위치(file->pos)는 영향을 받지 않습니다.
 * 실제로 읽은 바이트 수를 반환합니다. */
off_t file_read_at(struct file *file, void *buffer, off_t size, off_t file_ofs)
{
    return inode_read_at(file->inode, buffer, size, file_ofs); // 지정된 오프셋 위치에서 읽기
}


/* BUFFER에서 FILE로 SIZE 바이트를 파일의 현재 위치에서부터 씁니다.
 * 파일의 끝에 도달하면 SIZE보다 적은 바이트를 쓸 수 있습니다.
 * (보통 이런 경우 파일 크기를 늘리지만, 파일 크기 확장은 아직 구현되지 않았습니다.)
 * 파일의 현재 위치를 실제로 쓴 바이트 수만큼 이동시킵니다.
 * 실제로 쓴 바이트 수를 반환합니다. */
off_t file_write(struct file *file, const void *buffer, off_t size)
{
    off_t bytes_written = inode_write_at(file->inode, buffer, size, file->pos); // 현재 위치에서 쓰기 시작
    file->pos += bytes_written;    												// 실제로 쓴 바이트 수만큼 파일 위치를 이동
    return bytes_written;          												// 실제로 쓴 바이트 수 반환
}


/* BUFFER에서 FILE로 SIZE 바이트를 FILE_OFS 위치에서부터 씁니다.
 * 파일의 끝에 도달하면 SIZE보다 적은 바이트를 쓸 수 있습니다.
 * (보통 이런 경우 파일 크기를 늘리지만, 파일 크기 확장은 아직 구현되지 않았습니다.)
 * 파일의 현재 위치(file->pos)에는 영향을 미치지 않습니다.
 * 실제로 쓴 바이트 수를 반환합니다. */
off_t file_write_at(struct file *file, const void *buffer, off_t size, off_t file_ofs)
{
    return inode_write_at(file->inode, buffer, size, file_ofs); // 지정된 오프셋 위치에서 쓰기 시작
}


/* FILE의 기본 inode에 대한 쓰기 작업을 금지합니다.
 * file_allow_write()가 호출되거나 FILE이 닫힐 때까지 쓰기 작업이 금지됩니다. */
void file_deny_write(struct file *file)
{
    ASSERT(file != NULL);               // file 포인터가 NULL이 아닌지 확인

    if (!file->deny_write) {            // 파일이 현재 쓰기 허용 상태인지 확인
        file->deny_write = true;        // 파일의 쓰기 금지 플래그를 활성화
        inode_deny_write(file->inode);  // 파일의 inode에 대해 쓰기 작업을 금지
    }
}


/* FILE의 기본 inode에 대한 쓰기 작업을 다시 허용합니다.
 * (같은 inode를 열고 있는 다른 파일에 의해 여전히 쓰기가 금지될 수 있습니다.) */
void file_allow_write(struct file *file)
{
    ASSERT(file != NULL);               // file 포인터가 NULL이 아닌지 확인

    if (file->deny_write) {             // 파일이 현재 쓰기 금지 상태인지 확인
        file->deny_write = false;       // 파일의 쓰기 금지 플래그를 해제하여 쓰기 허용
        inode_allow_write(file->inode); // 파일의 inode에 대한 쓰기 작업 허용
    }
}


/* FILE의 크기를 바이트 단위로 반환합니다. */
off_t file_length(struct file *file)
{
    ASSERT(file != NULL);                  // file 포인터가 NULL이 아닌지 확인
    return inode_length(file->inode);      // 파일의 inode를 통해 파일 크기 반환
}


/* FILE의 현재 위치를 파일 시작점에서 NEW_POS 바이트만큼 떨어진 위치로 설정합니다. */
void file_seek(struct file *file, off_t new_pos)
{
    ASSERT(file != NULL);           // file 포인터가 NULL이 아닌지 확인
    ASSERT(new_pos >= 0);           // new_pos가 0 이상의 유효한 값인지 확인
    file->pos = new_pos;            // 파일의 현재 위치를 new_pos로 설정
}


/* FILE의 현재 위치를 파일 시작점에서부터의 바이트 오프셋으로 반환합니다. */
off_t file_tell(struct file *file)
{
    ASSERT(file != NULL);         // file 포인터가 NULL이 아닌지 확인
    return file->pos;             // 파일의 현재 위치 (바이트 오프셋) 반환
}
