/* Experimental trusted launcher/guardian. Link libSystem only, never libpython.
 * The guardian owns the child until waitpid: its PID cannot be recycled while
 * the guardian may signal it. Worker startup never inherits the liveness pipe.
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/task_special_ports.h>
#include <mach/clock.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern int sandbox_init(const char *, uint64_t, char **);
extern void sandbox_free_error(char *);
extern int sandbox_check(pid_t, const char *, int, ...);

#define MAX_SOURCE (1048576)
static void fail(const char *phase) {
    dprintf(STDOUT_FILENO, "{\"status\":\"error\",\"phase\":\"%s\"}\n", phase);
    _exit(70);
}
static void close_unrelated(void) {
    DIR *directory = opendir("/dev/fd");
    if (!directory) fail("descriptor_inventory");
    int inventory = dirfd(directory);
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        char *end = NULL;
        long fd = strtol(entry->d_name, &end, 10);
        if (end && !*end && fd > 2 && fd != inventory) close((int)fd);
    }
    closedir(directory);
}
static char *startup_authority(void) {
    mach_port_t task = mach_task_self();
    mach_port_t thread = mach_thread_self();
    mach_port_t host = mach_host_self();
    mach_port_t inspect = MACH_PORT_NULL, name_port = MACH_PORT_NULL, read_port = MACH_PORT_NULL;
    task_get_special_port(task, TASK_INSPECT_PORT, &inspect);
    task_get_special_port(task, TASK_NAME_PORT, &name_port);
    task_get_special_port(task, TASK_READ_PORT, &read_port);
    clock_serv_t system_clock = MACH_PORT_NULL, calendar_clock = MACH_PORT_NULL;
    host_get_clock_service(host, SYSTEM_CLOCK, &system_clock);
    host_get_clock_service(host, CALENDAR_CLOCK, &calendar_clock);
    const semaphore_t *clock_semaphore = (const semaphore_t *)dlsym(RTLD_DEFAULT, "clock_sem");
    mach_port_t bootstrap = MACH_PORT_NULL;
    if (task_get_special_port(task, TASK_BOOTSTRAP_PORT, &bootstrap) != KERN_SUCCESS) fail("bootstrap_inventory");
    mach_port_name_array_t names;
    mach_port_type_array_t types;
    mach_msg_type_number_t count, type_count;
    if (mach_port_names(task, &names, &count, &types, &type_count) != KERN_SUCCESS || count != type_count || count > 64) fail("mach_inventory");
    char *code = calloc(32768, 1);
    if (!code) fail("allocation");
    size_t used = (size_t)snprintf(code, 32768, "__slanggraph_startup_ports = [");
    for (mach_msg_type_number_t i = 0; i < count; ++i) {
        const char *kind = names[i] == task ? "task-self" : names[i] == thread ? "thread-self" : names[i] == host ? "host-self" : names[i] == bootstrap ? "bootstrap" : names[i] == inspect ? "task-inspect-self" : names[i] == name_port ? "task-name-self" : names[i] == read_port ? "task-read-self" : names[i] == system_clock ? "system-clock" : names[i] == calendar_clock ? "calendar-clock" : (clock_semaphore && names[i] == *clock_semaphore) ? "clock-semaphore" : (types[i] & MACH_PORT_TYPE_RECEIVE) ? "worker-local" : (types[i] & MACH_PORT_TYPE_DEAD_NAME) ? "dead-name" : "unclassified";
        if (!strcmp(kind, "unclassified")) {
            if (mach_port_destroy(task, names[i]) != KERN_SUCCESS) fail("mach_disposal");
            mach_port_type_t remaining;
            kern_return_t observed = mach_port_type(task, names[i], &remaining);
            if (observed != KERN_INVALID_NAME && !(observed == KERN_SUCCESS && remaining == MACH_PORT_TYPE_DEAD_NAME)) fail("mach_disposal_observation");
            kind = "removed";
        }
        used += (size_t)snprintf(code + used, 32768 - used, "%s{'name':%u,'rights':%u,'kind':'%s'}", i ? "," : "", names[i], types[i], kind);
    }
    snprintf(code + used, 32768 - used, "]\n");
    vm_deallocate(task, (vm_address_t)names, count * sizeof(*names));
    vm_deallocate(task, (vm_address_t)types, type_count * sizeof(*types));
    return code;
}
static char *read_source(int fd) {
    char *result = calloc(MAX_SOURCE + 1, 1);
    size_t offset = 0;
    if (!result) fail("allocation");
    for (;;) {
        ssize_t n = read(fd, result + offset, MAX_SOURCE - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 || (n == 0 && offset == 0)) fail("source");
        if (n == 0) break;
        offset += (size_t)n;
        if (offset == MAX_SOURCE) fail("source_limit");
    }
    close(fd);
    if (memchr(result, 0, offset)) fail("source_nul");
    return result;
}
static long positive(const char *s) {
    char *end = NULL;
    errno = 0;
    long n = strtol(s, &end, 10);
    if (errno || !end || *end || n <= 0 || n > INT_MAX) fail("argument");
    return n;
}
static double monotonic_now(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) fail("clock");
    return value.tv_sec + value.tv_nsec / 1000000000.0;
}
static void limit(int kind, rlim_t value) {
    struct rlimit r = {value, value};
    if (setrlimit(kind, &r)) fail("rlimit");
}
#define SYMBOL(name) __typeof__(&name) p_##name = (__typeof__(&name))dlsym(runtime, #name); if (!p_##name) fail("python_symbol")
#define CHECK(expression) do { PyStatus status = (expression); if (status._type != 0) fail("python_config"); } while (0)
static void worker(char **args) {
    /* args: request FD, response FD, profile FD, shim FD, library, stdlib,
     * extension root, CPU seconds, descriptor limit, startup ms, wall ms. */
    if (setpgid(0, 0)) fail("process_group");
    if (dup2((int)positive(args[0]), 0) < 0 || dup2((int)positive(args[1]), 1) < 0) fail("pipes");
    int nullfd = open("/dev/null", O_RDWR);
    if (nullfd < 0 || dup2(nullfd, 2) < 0) fail("diagnostics");
    if (nullfd > 2) close(nullfd);
    char *profile = read_source((int)positive(args[2]));
    char *shim = read_source((int)positive(args[3]));
    close_unrelated();
    char *authority = startup_authority();
    limit(RLIMIT_CORE, 0);
    limit(RLIMIT_CPU, (rlim_t)positive(args[7]));
    limit(RLIMIT_NOFILE, (rlim_t)positive(args[8]));
    char *error = NULL;
    if (sandbox_init(profile, 0, &error)) {
        if (error) sandbox_free_error(error);
        fail("seatbelt");
    }
    free(profile);
    if (sandbox_check(getpid(), NULL, 0) != 1) fail("seatbelt_observation");
    /* All dynamic initializers, Python startup imports and extension loading
     * happen under the final profile. There is no post-confinement exec. */
    void *runtime = dlopen(args[4], RTLD_NOW | RTLD_GLOBAL);
    if (!runtime) fail("dlopen");
    SYMBOL(PyConfig_InitIsolatedConfig);
    SYMBOL(PyConfig_SetBytesString);
    SYMBOL(PyWideStringList_Append);
    SYMBOL(Py_InitializeFromConfig);
    SYMBOL(PyConfig_Clear);
    SYMBOL(PyRun_SimpleString);
    SYMBOL(Py_FinalizeEx);
    PyConfig config;
    p_PyConfig_InitIsolatedConfig(&config);
    config.site_import = 0;
    config.use_environment = 0;
    config.write_bytecode = 0;
    config.install_signal_handlers = 0;
    config.parse_argv = 0;
    config.module_search_paths_set = 1;
#if PY_VERSION_HEX >= 0x030B0000
    config.safe_path = 1;
#endif
    CHECK(p_PyConfig_SetBytesString(&config, &config.program_name, "slanggraph-macos-worker"));
    for (int i = 5; i <= 6; ++i) {
        wchar_t path[PATH_MAX];
        size_t decoded = mbstowcs(path, args[i], PATH_MAX);
        if (decoded == (size_t)-1 || decoded >= PATH_MAX) fail("runtime_path");
        path[decoded] = 0;
        CHECK(p_PyWideStringList_Append(&config.module_search_paths, path));
    }
    CHECK(p_Py_InitializeFromConfig(&config));
    p_PyConfig_Clear(&config);
    if (p_PyRun_SimpleString(authority)) fail("authority_projection");
    free(authority);
    int status = p_PyRun_SimpleString(shim);
    free(shim);
    if (p_Py_FinalizeEx() < 0) status = -1;
    _exit(status == 0 ? 0 : 70);
}
int main(int argc, char **argv) {
    if (argc != 13 || strcmp(argv[1], "--guardian")) fail("arguments");
    char **args = argv + 2;
    signal(SIGPIPE, SIG_IGN);
    double startup = positive(args[9]) / 1000.0;
    double wall = positive(args[10]) / 1000.0;
    pid_t child = fork();
    if (child < 0) fail("fork");
    if (child == 0) worker(args);
    /* Close every worker resource in the guardian. Only controller liveness,
     * diagnostics and acknowledgement pipes remain. The guardian is outside
     * the child's process group and is never killed by its own killpg. */
    close_unrelated();
    printf("{\"status\":\"spawned\",\"pid\":%d}\n", child);
    fflush(stdout);
    double deadline = monotonic_now() + startup;
    int killed = 0, armed = 0, status = 0;
    char command[4];
    size_t used = 0;
    for (;;) {
        pid_t observed = waitpid(child, &status, WNOHANG);
        if (observed == child) break;
        if (observed < 0) fail("waitpid");
        if (!killed && monotonic_now() >= deadline) {
            kill(child, SIGKILL); killed = 1;
        }
        struct pollfd input = {0, POLLIN | POLLHUP, 0};
        int ready = poll(&input, 1, 10);
        if (ready < 0 && errno != EINTR) { kill(child, SIGKILL); killed = 1; }
        if (ready > 0) {
            ssize_t n = read(0, command + used, sizeof(command) - used);
            if (n <= 0) { kill(child, SIGKILL); killed = 1; }
            else {
                used += (size_t)n;
                if (used == sizeof(command)) {
                    if (!armed && !memcmp(command, "ARM\n", 4)) {
                        armed = 1;
                        deadline = monotonic_now() + wall;
                        puts("{\"status\":\"armed\"}"); fflush(stdout);
                    } else { kill(child, SIGKILL); killed = 1; }
                    used = 0;
                }
            }
        }
    }
    printf("{\"status\":\"reaped\",\"pid\":%d,\"wait_status\":%d}\n", child, status);
    fflush(stdout);
    return 0;
}
