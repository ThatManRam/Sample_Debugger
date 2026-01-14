#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h> 
#include <sys/ptrace.h>
#include <errno.h>
#include <string.h>

static void die(const char *msg) {
    perror(msg);
    exit(1);
}


int main(int argc, char *argv[]) {

    if(argc <=1){
        printf("please add argument");
        return -1;
    }
    
    printf("the program you hooked is %s\n", argv[1]);

    pid_t child = fork();

    if (child == -1){
        die("fork");
    }

    if (child == 0) {
        // Child: allow tracing then exec
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
            die("PTRACE_TRACEME");
            

        execvp(argv[1], &argv[1]);
        die("execl");
    }
    int status = 0;
    if (waitpid(child, &status, 0) == -1) die("waitpid");

    if (ptrace(PTRACE_CONT, child, 0, 0) == -1)
    die("PTRACE_CONT");
    
    if (waitpid(child, &status, 0) == -1) die("waitpid");


    return 0;
}