#include <lean/lean.h>

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern lean_object *initialize_worker_x2droute_Main(uint8_t builtin);
extern lean_object *argus_worker_route_check(lean_object *input);

static pthread_once_t argus_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t argus_lock = PTHREAD_MUTEX_INITIALIZER;
static int argus_initialized = 0;

static void argus_initialize(void) {
    lean_object *result = initialize_worker_x2droute_Main(1);
    if (!lean_io_result_is_ok(result)) {
        lean_dec_ref(result);
        return;
    }
    lean_dec_ref(result);
    lean_io_mark_end_initialization();
    lean_init_task_manager();
    argus_initialized = 1;
}

/*
 * Return the response length, -1 on a refused/invalid request, -2 when the
 * caller's output buffer is too small, and -3 on initialization failure.
 */
__attribute__((visibility("default"))) int argus_worker_route_check_json(
    const char *input,
    size_t input_size,
    char *output,
    size_t output_size
) {
    if (input == NULL || output == NULL || input_size == 0) {
        return -1;
    }
    pthread_once(&argus_once, argus_initialize);
    if (!argus_initialized) {
        return -3;
    }
    pthread_mutex_lock(&argus_lock);
    lean_object *request = lean_mk_string_from_bytes(input, input_size);
    lean_object *response = argus_worker_route_check(request);
    size_t response_size = lean_string_size(response) - 1;
    int status = -1;
    if (response_size != 0) {
        if (response_size >= output_size) {
            status = -2;
        } else {
            memcpy(output, lean_string_cstr(response), response_size);
            output[response_size] = '\0';
            status = (int)response_size;
        }
    }
    lean_dec_ref(response);
    pthread_mutex_unlock(&argus_lock);
    return status;
}
