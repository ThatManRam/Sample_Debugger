#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <errno.h>
#include <string.h>

typedef struct {
    unsigned long long addr;
    long saved_word;
    int enabled;
} breakpoint_t;

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static long peek_word(pid_t pid, unsigned long long addr) {
    errno = 0;
    long v = ptrace(PTRACE_PEEKDATA, pid, (void*)addr, 0);
    if (errno) die("PTRACE_PEEKDATA");
    return v;
}

static void poke_word(pid_t pid, unsigned long long addr, long data) {
    if (ptrace(PTRACE_POKEDATA, pid, (void*)addr, (void*)data) == -1)
        die("PTRACE_POKEDATA");
}

static void cont(pid_t pid) {
    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
        die("PTRACE_CONT");
}

static void singlestep(pid_t pid) {
    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
        die("PTRACE_SINGLESTEP");
}

static void get_regs(pid_t pid, struct user_regs_struct *regs) {
    if (ptrace(PTRACE_GETREGS, pid, 0, regs) == -1)
        die("PTRACE_GETREGS");
}

static void set_regs(pid_t pid, struct user_regs_struct *regs) {
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) == -1)
        die("PTRACE_SETREGS");
}

static void enable_breakpoint(pid_t pid, breakpoint_t *bp) {
    if (bp->enabled) return;

    long word = peek_word(pid, bp->addr);
    bp->saved_word = word;

    long patched = (word & ~0xff) | 0xcc; // x86/x86_64 INT3
    poke_word(pid, bp->addr, patched);

    bp->enabled = 1;
}

static void disable_breakpoint(pid_t pid, breakpoint_t *bp) {
    if (!bp->enabled) return;
    poke_word(pid, bp->addr, bp->saved_word);
    bp->enabled = 0;
}

int main(int argc, char *argv[]) {
    if (argc <= 1) {
        fprintf(stderr, "usage: %s <target> [args...]\n", argv[0]);
        return 1;
    }

    printf("the program you hooked is %s\n", argv[1]);


    while (1) {

        
        char inp[64];

        if (!fgets(inp, sizeof(inp), stdin)) return 0;
        inp[strcspn(inp, "\n")] = '\0';

        if (strcmp(inp, "exit") == 0) return 0;

        else if (strcmp(inp, "help") == 0) printf("exit - to exit the program\nbreak - to set a break point\n");

        else if (strcmp(inp, "break") == 0) {
            printf("Where would you like to break (hex, e.g. 0x401156): ");
            fflush(stdout);

            if (!fgets(inp, sizeof(inp), stdin)) return 0;
            inp[strcspn(inp, "\n")] = '\0';

            unsigned long long bp_addr = strtoull(inp, NULL, 16);

            pid_t child = fork();
            if (child == -1) die("fork");

            if (child == 0) {
                if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
                    die("PTRACE_TRACEME");
                execvp(argv[1], &argv[1]);
                die("execvp");
            }

            int status = 0;

            // 1) Wait for initial SIGTRAP stop after exec
            if (waitpid(child, &status, 0) == -1) die("waitpid");
            if (!WIFSTOPPED(status)) {
                fprintf(stderr, "Child did not stop as expected.\n");
                return 1;
            }

            // 2) Install breakpoint while child is STOPPED
            breakpoint_t bp = { .addr = bp_addr, .saved_word = 0, .enabled = 0 };
            enable_breakpoint(child, &bp);

            // 3) Run and handle hits
            cont(child);

            for (;;) {
                if (waitpid(child, &status, 0) == -1) die("waitpid");

                if (WIFEXITED(status)) {
                    printf("Target exited (%d)\n", WEXITSTATUS(status));
                    break;
                }
                if (!WIFSTOPPED(status)) continue;

                int sig = WSTOPSIG(status);
                if (sig == SIGTRAP) {
                    struct user_regs_struct regs;
                    get_regs(child, &regs);

                    if (regs.rip == bp.addr + 1) {
                        printf("Hit breakpoint at 0x%llx\n", bp.addr);

                        regs.rip = bp.addr;
                        set_regs(child, &regs);

                        disable_breakpoint(child, &bp);
                        singlestep(child);

                        if (waitpid(child, &status, 0) == -1) die("waitpid");

                        enable_breakpoint(child, &bp);
                    }
                    cont(child);
                } else {
                    // For now, just continue (note: this suppresses delivery of sig)
                    cont(child);
                }
            }
        }
        else{
            printf("type help to get options\n");
        }
    }
}
