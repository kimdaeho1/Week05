/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */

// 가용 리스트 조작을 위한 기본 상수 및 매크로 정의

#define WSIZE 4 // 1워드, 헤더와 푸터 사이즈 4.
#define DSIZE 8 // 2워드 사이즈 8
#define CHUNKSIZE (1<<12) // 확장을 위한 기본크기 CHUNKSIZE

#define MAX(x, y) ((x) > (y) ? (x) : (y))   //

// pack a size and allocated bit into a word
#define PACK(size, alloc) ((size) | (alloc))    //크기와 할당 비트를 통합해서 헤더와 풋터에 저장할 수 있는 값을 리턴한다.

// read and write a word at address p
#define GET(p)          (*(unsigned int *)(p))      // GET메크로는 인자 p가 참조하는 워드를 읽어서 리턴한다 여기서 캐스팅이 중요한데, 인자 p는 대개 void*의 포인터이고, 직접 역참조 할 수 없다.
                                                    // p라는 포인터를 unsigned int 형으로 변환하고, 이후 p가 가리키는 메모리 위치에 저장된 4바이트 값을 읽어온다.
#define PUT(p, val)     (*(unsigned int *)(p) = (val)) //마찬가지로 PUT매크로는 인자 p가 가리키는 워드에 val을 저장한다

// read the size and allocated fields from address p
#define GET_SIZE(p)     (GET(p) & ~0x7) //SIZE와ALLOC은 주소 p에 있는 헤더 또는 풋터에 size와 할당 비트를 리턴한다. //블록의 크기 정보를 얻기 위해 마지막 3비트를 제외한 나머지 비트 반환.
#define GET_ALLOC(p)    (GET(p) & 0x1)  //블록 포인터 bp가 주어지면, HDRP와FTRP가 각각 블록 헤더와 풋터를 가리키는 포인터를 리턴한다. //할당 되었는지 여부를 판단하는 것

// Given block pointer bp, compute address of its header and footer
#define HDRP(bp)    ((char *)(bp) - WSIZE)  //bp는 블록의 시작을 가리키는데, payload영역을 가리킴. 여기에서 4바이트를 빼서(앞으로 가서) 헤더의 위치를 계산함.
#define FTRP(bp)    ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE) //payload에서 전체값을 더한 값이 되기 때문에, SIZE상 전체 + 헤더를 더한 꼴이 됨. 그래서 DSIZE로 8바이트를 뺴야 풋터의 위치가 나옴

// Given block pointer bp, compute address of next and previous blocks
#define NEXT_BLKP(bp)   ((char *)(bp) + GET_SIZE(((char *)(bp) - WSIZE))) //현재 페이로드 위치에서 나의 헤더에서 저장된 사이즈를 더함(나의 전체 메모리를 더함) = 다음 페이로드 시작 주소 가리킴
#define PREV_BLKP(bp)   ((char *)(bp) - GET_SIZE(((char *)(bp) - DSIZE))) //현재 페이로드 위치에서 이전의 헤더에서 저장된 사이즈를 뺌(상대의 전체 메모리를 뺌) = 이전 페이로드 시작 주소 가리킴

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "2team",
    /* First member's full name */
    "kimdaeho",
    /* First member's email address */
    "itovel100@gmail.com",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""
};

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8 //2워드짜리를 쓴다는 이야기 같고

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)   //비트 뺸 사이즈가 될거고


#define SIZE_T_SIZE (ALIGN(sizeof(size_t))) //정렬하는 친구


static char *heap_listp; //?? 이렇게 선언하는거 맞냐. 전역변수로 할당하지 않으려면 위에 함수 주루륵 선언하는거밖에 방법이 없나?  
char *old_bp = NULL;
static void *find_fit(size_t asize)
{
    char *bp = (old_bp != NULL) ? old_bp : heap_listp;  // old_bp != NULL이 참이면 oldbp, 거짓이면 heap_listp
    while(GET_SIZE(HDRP(bp)) > 0) //힙의 끝까지
    {
        if (GET_ALLOC(HDRP(bp)) == 0 && GET_SIZE(HDRP(bp)) > asize)
        {
            old_bp = bp;
            return bp;
        }
        else{
            bp = NEXT_BLKP(bp);
        }
    }

    old_bp = NULL;
    return NULL;
    //할당기가 요청한 크기를 조정후, 적절한 가용 블록을 가용 리스트에서 검색한다.
    //맞는 블록을 찾으면 할당기는 요청한 블록을 배치하고, 옵션으로 초과부분을 분할하고, 새롭게 할당한 블록을 리턴한다. 
}

static void place(void *bp, size_t asize)
{   
    size_t csize = GET_SIZE(HDRP(bp));

    if ((csize - asize) >= (2*DSIZE)) //만약 헤더와 풋터, 그리고 페이로드를 넣을 공간(16비트)보다 사이즈가 크다면
    {
        PUT(HDRP(bp), PACK(asize, 1));
        PUT(FTRP(bp), PACK(asize, 1));
        bp = NEXT_BLKP(bp);
        PUT(HDRP(bp), PACK(csize - asize, 0));
        PUT(FTRP(bp), PACK(csize - asize, 0));
    }
    else
    {
        PUT(HDRP(bp), PACK(csize, 1));
        PUT(FTRP(bp), PACK(csize, 1));
    }
}


static void *coalesce(void *bp)
{
    size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp))); //next와 prev는 bp의 이전블록이 할당되었는지 의 여부를 0과 1로 조사함
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp))); //prev는 이전 블록의 푸터에서, next는 다음 블록의 헤더에서 0과 1을 뽑아옴
    size_t size = GET_SIZE(HDRP(bp));   //현재 블록의 크기를 가져옴

    if (prev_alloc && next_alloc) { //둘다 1이면 병합이 안됨
        return bp; //case 1
    }

    else if (prev_alloc && !next_alloc) {   //이전은 할당되고 다음은 가용인경우
        size += GET_SIZE(HDRP(NEXT_BLKP(bp))); //case2  //현재와 다음 블록을 병합한다. 다음 블록이 가용이니까 지금과 다음 블록의 크기를 업데이트시킴
        PUT(HDRP(bp), PACK(size, 0)); //현재 블록의 헤더를 업데이트하여 크기와 가용상태를 변경
        PUT(FTRP(bp), PACK(size, 0));   //다음 블록의 푸터를 업뎃하면됨
    }

    else if (!prev_alloc && next_alloc) {
        size += GET_SIZE(HDRP(PREV_BLKP(bp))); //case 3 이전은 가용이고 다음이 할당인 경우
        PUT(FTRP(bp), PACK(size, 0));           // 이전 블록의 헤더를 업데이트해서 크기와 가용상태 설정
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));    //현재 블록의 푸터를 업뎃하여 새로운 크기와 가용상태 설정
        bp = PREV_BLKP(bp); //포인터를 이전으로 반환
    }

    else {
        size += GET_SIZE(HDRP(PREV_BLKP(bp))) + GET_SIZE(FTRP(NEXT_BLKP(bp)));
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));    //둘다 가용상태면 이전 블록의 헤더
        PUT(FTRP(NEXT_BLKP(bp)), PACK(size, 0));    // 다음 블록의 헤더에 0설정.
        bp = PREV_BLKP(bp);
    }
    old_bp = bp;
    return bp;
}

//새 가용 블록으로 힙 확장하기
static void *extend_heap(size_t words) //워드의 수를 계산해야하니까(CHUNKSIZE/WORDS). 짝수면 Wsize를 곱해서, 홀수면 +1후 Wsize를 곱해서 정렬하기 위해
{
    char *bp;
    size_t size;

    size = (words % 2) ? (words + 1) * WSIZE : words * WSIZE;   // 힙이 초기화될때, malloc이 적당한 맞춤을 찾지 못했을때, 정렬을 유지하기 위해서 요청한 크기를 2워드의 배수로 반올림하고
                                                            //크기가 홀수일 경우.
                                                            //추가적인 힙 공간을 요청
    if ((long)(bp = mem_sbrk(size)) == -1){                 //메모리 시스템으로부터 추가적인 힙 공간을 요청한다
        return NULL;
    }
    //mem_sbrk의 호출에서 반환값을 저장. 힙을 size만큼 확장후 확장된 메모리 영역의 시작 주소 반환.
                                            //힙은 더블 워드 경계에서 시작하고, extend_heap 으로 가는 모든 호출은 에필로그 브록의 헤더에 곧이어서 더블 워드 정렬된 메모리 블록을 리턴한다
    PUT(HDRP(bp), PACK(size, 0));           //새 가용 블록의 헤더 설정
    PUT(FTRP(bp), PACK(size, 0));           //새 가용 블록의 푸터 설정
    PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1));   //에필로그 블록의 헤더

    return coalesce(bp);                    //마지막으로 이전 힙이 가용 블록으로 끝났다면, 두개의 가용 블록을 통합하기 위해 이 함수를 호출하고 통합된 블록의 블록 포인터를 리턴한다
}

/* 
 * mm_init - initialize the malloc package.
 */

//최초 가용 블록으로 힙 생성하기
int mm_init(void)
{
    //create the initial empty heap


    if ((heap_listp = mem_sbrk(4*WSIZE)) == (void *)-1) { //mem_sbrk를 호출해서 힙을 CHUNKSIZE바이트로 확장하고 초기 가용 블록을 생성한다.
        return -1;
    }
    PUT(heap_listp, 0); //메모리 블록의 시작 부분. 초기화를 위한 부분?
    PUT(heap_listp + (1*WSIZE), PACK(DSIZE, 1)); //prologue header 묵시적 가용 리스트의 불변형식인 prologue블록 2개와 
    PUT(heap_listp + (2*WSIZE), PACK(DSIZE, 1)); //1은 블록이 할당되었음을 나타냄 그러니까, 책 한권의 정보를 저장하는데 책 앞면과 뒷면에 정보를 저장하고, 책의 전체 크기를 알려주는 DSIZE가 되는것.
    PUT(heap_listp + (3*WSIZE), PACK(0,1)); //힙의 끝을 나타내고 더이상 확장되지 않음
    heap_listp += (2*WSIZE);    //처음 시작 부분

    //extend the empty heap with a free block of CHUNKSIZE bytes    
    if (extend_heap(CHUNKSIZE/WSIZE) == NULL){  
        return -1;
    }
    return 0;
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *bp)
{
    size_t size = GET_SIZE(HDRP(bp));  //해제할 메모리 블록의 포인터. ptr이 가리키는 블록의 헤더 위치 계산, 해당 블록의 크기를 가져오기

    PUT(HDRP(bp), PACK(size, 0));      //헤더와 푸터를 0으로설정해서 할당되지 않음을 설정하기.
    PUT(FTRP(bp), PACK(size, 0));
    coalesce(bp);                      //이거 호출해서 합칠거임.
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{

    size_t asize; 
    size_t extendsize; //맞지 않는다면 힙을 늘려야하니까
    char *bp;

    if (size == 0)
        return NULL;


    if (size <= DSIZE)  //최수 16바이트 크기의 블록을 구성한다 8바이트는정렬 요건을, 8바이트는 헤더와 풋터를 위한 공간을.
        asize = 2*DSIZE;
    else 
        asize = ALIGN(size + DSIZE); //만약 8바이트를 넘는다면, 오버헤드 바이트를 추가하고, 인접 8의 배수로 반올림
    

    if ((bp = find_fit(asize)) != NULL) {   //적절한 가용 블록이 있다면
        place(bp, asize);                   //옵션으로 초과부분을 분할하고 할당한 블록을 리턴
        return bp;
    }

    extendsize = MAX(asize, CHUNKSIZE); //만약 맞지 않았다면 
    if ((bp = extend_heap(extendsize/WSIZE)) == NULL) //힙을 새로운 가용 블록으로 확장하고 요청한 블록을 새 가용 블록에 배치하고, 필요한 경우 
        return NULL;
    place(bp, asize);    //요청한 블록을 새 가용 블록에 배치, 블록의 포인터 리턴
    return bp;


    // int newsize = ALIGN(size + SIZE_T_SIZE);
    // void *p = mem_sbrk(newsize);             //메모리 확장
    // if (p == (void *)-1)                     //오류 처리
    // return NULL;
    // else {                                   //메모리 크기 저장 및 반환
    //     *(size_t *)p = size;
    //     return (void *)((char *)p + SIZE_T_SIZE);
    // }
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
    void *oldptr = ptr;
    void *newptr;
    size_t copySize;
    
    newptr = mm_malloc(size);   //새로운 크기의 메모리 블록을 할당. 이때의 주소를 newptr에 저장. (데이터는 넘어오지 않은 상태)
    if (newptr == NULL)         //메모리 할당이 실패했다면, 함수는 NULL을 반환
      return NULL;
    copySize = GET_SIZE(HDRP(oldptr));  //기존 블록을 가리키는 oldptr을 호출해서 기존 블록의 크기를 가져옴
    if (size < copySize)    //만약 기존의 사이즈가 더 크다면
      copySize = size;      //size를 조정하고
    memcpy(newptr, oldptr, copySize);   //memcpy는 string.h 헤더파일에 선언되어있음. 메모리의 한 위치에서 다른 위치로 복사하는데 사용됨.
    mm_free(oldptr);    //기존 블록을 해제하는 방식. 기존 블록의 크기가 조정된다면, 기존 블록의 데이터를 복사하고 기존 블록을 해제한다.
    return newptr;      //이후 재할당하는 과정을 거친다.
}


