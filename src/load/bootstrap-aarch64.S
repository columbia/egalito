// Created based on glibc start up file for aarch64.
#ifdef __LP64__
# define AARCH64_R(NAME)    R_AARCH64_ ## NAME
# define PTR_REG(n)     x##n
# define PTR_LOG_SIZE       3
# define DELOUSE(n)
#else
# define AARCH64_R(NAME)    R_AARCH64_P32_ ## NAME
# define PTR_REG(n)     w##n
# define PTR_LOG_SIZE       2
# define DELOUSE(n)     mov     w##n, w##n
#endif

#define PTR_SIZE    (1<<PTR_LOG_SIZE)

.global initial_stack
.global entry
.global _start2
.global _set_tpidr_el0

.section .bss
.align 8    //only GOT requires 8-byte alignment?
initial_stack:
    .skip   8
saved_x0:
    .skip   8
entry:
    .skip   PTR_SIZE


/* This is the canonical entry point, usually the first thing in the text
	 segment.

	 Note that the code in the .init section has already been run.
	 This includes _init and _libc_init


	 At this entry point, most registers' values are unspecified, except:

	 x0/w0	Contains a function pointer to be registered with `atexit'.
		This is how the dynamic linker arranges to have DT_FINI
		functions called for shared libraries that have been loaded
		before this code runs.

	 sp		The stack contains the arguments and environment:
		0(sp)			argc
		8(sp)			argv[0]
		...
		(8*argc)(sp)		NULL
		(8*(argc+1))(sp)	envp[0]
		...
					NULL
 */

	.text
	.globl _start
	.type _start,#function
_start:
		# save for _start2
		add     x2, sp, #0
		ldr     x1, =initial_stack
		str     x2, [x1]
		#adrp    x1, :pg_hi21:initial_stack
		#str     x2, [x1, #:lo12:initial_stack]
		ldr     x1, =saved_x0
		str     x0, [x1]
		#adrp    x1, :pg_hi21:saved_x0
		#str     x0, [x1, #:lo12:saved_x0]

	/* Create an initial frame with 0 LR and FP */
	mov	x29, #0
	mov	x30, #0

	/* Setup rtld_fini in argument register */
	mov	x5, x0

	/* Load argc and a pointer to argv */
	ldr	PTR_REG (1), [sp, #0]
	add	x2, sp, #PTR_SIZE

	/* Setup stack limit in argument register */
	mov	x6, sp

#ifdef SHARED
				adrp    x0, :got:main
	ldr     PTR_REG (0), [x0, #:got_lo12:main]

				adrp    x3, :got:__libc_csu_init
	ldr     PTR_REG (3), [x3, #:got_lo12:__libc_csu_init]

				adrp    x4, :got:__libc_csu_fini
	ldr     PTR_REG (4), [x4, #:got_lo12:__libc_csu_fini]
#else
	/* Set up the other arguments in registers */
	ldr	PTR_REG (0), =main
	ldr	PTR_REG (3), =__libc_csu_init
	ldr	PTR_REG (4), =__libc_csu_fini
#endif

	/* __libc_start_main (main, argc, argv, init, fini, rtld_fini,
						stack_end) */

	/* Let the libc call main and exit with its return code.  */
	bl	__libc_start_main

	/* should never get here....*/
	bl	abort

_start2:
    ldr     x1, =initial_stack
    ldr     x1, [x1]
    #adrp    x1, :pg_hi21:initial_stack
    #ldr     x1, [x1, #:lo12:initial_stack]
    mov     sp, x1
    ldr     x1, =saved_x0
    ldr     x0, [x1]
    #adrp    x1, :pg_hi21:saved_x0
    #ldr     x0, [x1, #:lo12:saved_x0]

    ldr     x1, =entry
    ldr     x1, [x1]
    #adrp    x1, :pg_hi21:entry
    #ldr     x1, [x1, #:lo12:entry]
    br      x1
    bl      abort

_set_tpidr_el0:
    msr     tpidr_el0, x0
    ret

	/* Define a symbol for the first piece of initialized data.  */
	.data
	.globl __data_start
__data_start:
	.long 0
	.weak data_start
	data_start = __data_start

