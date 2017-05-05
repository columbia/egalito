#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv, char **envp) {
    printf("note: envp is %lx\n", envp);
    printf("note: *envp is %s\n", *envp);
    printf("getenv: PATH=%s\n", getenv("PATH"));
    puts("iterating through envp manually:");
    for(char **env = envp; *env; env ++) {
        puts(*env);
    }
    return 0;
}
