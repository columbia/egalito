#include <alloca.h>
#include <string.h>
int __attribute__((noinline)) func___(int a, int b, int c, int d,
                                    int e, int f, int g, int h, int i)
{
    return a + b + c + d + e + f + g + h + i;
}

int __attribute__((noinline)) func__(int a, int b, int c, int d,
                                    int e, int f, int g, int h, int i)
{
#ifdef ARCH_AARCH64
    asm volatile("mov x18, x0" ::: "x18");
#endif

    return func___(a, b, c, d, e, f, g, h, i) + func___(i, h, g, f, e, d, c, b, a);
}

int __attribute__((noinline)) func_(int a, int b, int c, int d,
                                    int e, int f, int g, int h, int i)
{
#ifdef ARCH_AARCH64
    asm volatile("mov x18, x0" ::: "x18");
#endif

    return func__(a, b, c, d, e, f, g, h, i);
}

/* ---------------------------------------------------------------- */

int __attribute__((noinline)) funcB(void *p)
{
    return *(unsigned long *)p ? 3 : 2;
}

int __attribute__((noinline)) funcA(int i)
{
    void *p = alloca(i);
#ifdef ARCH_AARCH64
    asm volatile("mov x18, x0" ::: "x18");
#endif
    *(unsigned long *)p = 1;

    return funcB(p);
}

/* ---------------------------------------------------------------- */

struct s {
    int i;
};

int __attribute__((noinline)) func3(void *s)
{
    return ((struct s *)s)->i == 0 ? 0 : 1;
}

// uses x29
int __attribute__((noinline)) func2(int a)
{
    struct s ls, ls2;
    ls.i = a;
    ls2.i = 1;
#ifdef ARCH_AARCH64
    asm volatile("mov x18, x0" ::: "x18");
#endif

    return (a == 2) ? func3(&ls) : func3(&ls2);
}

// epilogue is only 'ret'
int __attribute__((noinline)) func1(int a, int b)
{
#ifdef ARCH_AARCH64
    asm volatile("mov x18, x0" ::: "x18");
#endif
    return (a == 2) ? 1 : func2(b);
}

/* ---------------------------------------------------------------- */

// epilogue is only 'ret'
int __attribute__((noinline)) func(int a, int b)
{
#ifdef ARCH_AARCH64
    asm volatile("mov x18, x0" ::: "x18");
#endif
    return (a == 1) ? 1 : func2(b);
}

/* ---------------------------------------------------------------- */

int main(int argc, char **argv)
{
    funcA(argc);
    func_(argc, argc + 1, argc + 2, argc + 3,
          argc + 4, argc + 5, argc + 6, argc + 7, argc + 8);
    return func(argc, argc << 1) + func1(argc, argc << 1);
}

