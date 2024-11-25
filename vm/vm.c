/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "lib/kernel/hash.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: Insert the page into the spt. */
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = malloc(sizeof(struct page));
	struct hash_elem *e;
	if (page == NULL)
	{
		return NULL;
	}
	
   	 //va에 해당하는 hash_elem 찾기
	page->va = pg_round_down(va);
	e = hash_find(&spt->hash_table, &page->hash_elem);
	
   	 //있으면 e에 해당하는 페이지 반환
	if (e != NULL)
	{
		struct page *found_page = hash_entry(e, struct page, hash_elem);
		free(page);
		return found_page;
	}
	else
	{
		free(page);
		return NULL;
	}
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;

	if (is_user_vaddr(page->va))
	{
		if (spt_find_page(spt, page->va) == NULL)
		{
			hash_insert(&spt->hash_table, &page->hash_elem);
			succ = true;
		}
	}
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
struct frame *frame = (struct frame*)malloc(sizeof(struct frame)); 
	/* TODO: Fill this function. */
   	// user_pool 에서 frame 가져오고, kva return해서 frame에 넣어준다.
	frame->kva = palloc_get_page(PAL_USER);
	
	if(frame->kva == NULL){ //frame에서 가용한 page가 없다면
		free(frame);
		PANIC("todo");
	}

	frame->page = NULL; //새 frame을 가져왔으니 page의 멤버를 초기화
	
	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
struct page *page = NULL;

	/* 물리 프레임과 연결을 할 페이지를 SPT를 통해서 찾아준다.*/
	page = spt_find_page(&thread_current()->spt, va);

	if (page == NULL)
		return false;
	return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame();
	if (frame == NULL)
	{
		return false;
	}

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	/* 페이지 테이블 항목을 삽입하여 페이지의 VA를 프레임의 PA에 매핑합니다. */
	/* pml4_get_page는 가상주소를 넣어 해당 물리주소를 찾고 그에 해당하는
	커널 가상 주소를 반환한다.*/
	/* pml4_set_page는 사용자 가상 페이지 UPAGE에서 커널 가상 주소 KPAGE로 
	식별된 물리 프레임에 대한 페이지 맵 레벨 4 PML4에 매핑을 추가한다. */

	//가상 주소와 물리 주소 매핑
	if (pml4_get_page(thread_current()->pml4, page->va) == NULL)
	{
		if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable))
		{
			vm_dealloc_page(page);
			return false;
		}
	}
	/* 해당 페이지를 물리 메모리에 올려준다.*/
	return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->hash_table, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}
