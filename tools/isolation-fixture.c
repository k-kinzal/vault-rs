/* PUBLIC TEST FIXTURE. Native OS probes; never linked into the product. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach/mach.h>
#endif
static void denied(const char *path, int flags) {
    int fd = open(path, flags);
    assert(fd < 0 && errno == EACCES);
}
static void groups(void) {
    gid_t values[256];
    int n = getgroups(256, values);
    assert(n >= 0);
    for (int i = 0; i < n; ++i) assert(values[i] == getgid());
}
static void memory(pid_t pid, const char *fd) {
#ifdef __APPLE__
    (void)fd;
    mach_port_t port = MACH_PORT_NULL;
    assert(task_for_pid(mach_task_self(), pid, &port) != KERN_SUCCESS);
#else
    char path[256];
    assert(snprintf(path, sizeof(path), "/proc/%d/mem", pid) > 0);
    denied(path, O_RDONLY);
    if (fd) {
        assert(snprintf(path, sizeof(path), "/proc/%d/fd/%s", pid, fd) > 0);
        denied(path, O_RDONLY);
    }
#endif
}
int main(int argc, char **argv) {
    assert(argc >= 2);
    alarm(15);
    if (!strcmp(argv[1], "spin")) { for (;;) pause(); }
    if (!strcmp(argv[1], "ai")) {
        assert(argc == 5 && getuid() == 1000);
        puts("PROBE: native AI process entered"); fflush(stdout);
        denied("/opt/vault-isolation/private/key", O_RDONLY);
        denied(argv[3], O_WRONLY);
        memory((pid_t)atoi(argv[2]), NULL);
        puts("PROBE: direct broker invocation from AI identity"); fflush(stdout);
        pid_t child = fork(); assert(child >= 0);
        if (!child) {
            execl(argv[4], argv[4], "broker", "--config", "/opt/vault-isolation/private/key", "--verification-run", (char *)NULL);
            _exit(127);
        }
        int status; assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && WEXITSTATUS(status) != 0 && WEXITSTATUS(status) != 127);
        puts("PASS: separate AI UID cannot read broker state, modify measured code, or invoke broker");
        return 0;
    }
    assert(getuid() >= 10000 && getgid() == getuid());
    groups();
    assert(!getenv("VAULT_PARENT_ONLY") && !getenv("LD_PRELOAD"));
    if (!strcmp(argv[1], "worker")) {
        assert(argc == 4);
        puts("PROBE: native workload entered"); fflush(stdout);
        denied("/opt/vault-isolation/private/key", O_RDONLY);
        memory((pid_t)atoi(argv[2]), argv[3]);
        errno = 0; assert(setuid(0) == -1 && errno == EPERM);
    } else assert(!strcmp(argv[1], "deployment"));
    const char expected[] = "SYNTHETIC AUTHORIZED SECRET";
    char input[sizeof(expected) + 1];
    size_t count = fread(input, 1, sizeof(input), stdin);
    assert(count == sizeof(expected)-1 && !memcmp(input, expected, count) && feof(stdin));
    puts(!strcmp(argv[1], "deployment") ? "WORKLOAD_OK" : "PASS: native worker received only the authorized plaintext; keys/memory/FDs denied");
    return 0;
}
