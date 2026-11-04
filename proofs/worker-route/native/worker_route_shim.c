#include <lean/lean.h>

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern lean_object *initialize_worker_x2droute_Main(uint8_t builtin);
extern lean_object *argus_worker_route_check(lean_object *input);
extern lean_object *argus_worker_route_prepare(lean_object *input);
extern lean_object *argus_worker_route_check_prepared(
    lean_object *prepared,
    lean_object *events
);

struct argus_prepared_route {
    lean_object *value;
};

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

/* Parse the invocation-stable binding and certificate into a retained Lean
 * value. NULL means initialization, allocation, or validation failed. */
__attribute__((visibility("default"))) void *argus_worker_route_prepare_json(
    const char *input,
    size_t input_size
) {
    if (input == NULL || input_size == 0) {
        return NULL;
    }
    pthread_once(&argus_once, argus_initialize);
    if (!argus_initialized) {
        return NULL;
    }
    struct argus_prepared_route *handle = malloc(sizeof(*handle));
    if (handle == NULL) {
        return NULL;
    }
    handle->value = NULL;
    pthread_mutex_lock(&argus_lock);
    lean_object *request = lean_mk_string_from_bytes(input, input_size);
    lean_object *result = argus_worker_route_prepare(request);
    if (!lean_is_scalar(result)) {
        lean_object *value = lean_ctor_get(result, 0);
        lean_inc(value);
        handle->value = value;
    }
    lean_dec_ref(result);
    pthread_mutex_unlock(&argus_lock);
    if (handle->value == NULL) {
        free(handle);
        return NULL;
    }
    return handle;
}

/* Check a cumulative event trace against the retained proved certificate.
 * The response is the Lean-derived phase name, not a second JSON envelope. */
__attribute__((visibility("default"))) int argus_worker_route_check_prepared_json(
    void *opaque,
    const char *events,
    size_t events_size,
    char *output,
    size_t output_size
) {
    struct argus_prepared_route *handle = opaque;
    if (handle == NULL || handle->value == NULL || events == NULL ||
        output == NULL || events_size == 0) {
        return -1;
    }
    pthread_once(&argus_once, argus_initialize);
    if (!argus_initialized) {
        return -3;
    }
    pthread_mutex_lock(&argus_lock);
    lean_inc(handle->value);
    lean_object *request = lean_mk_string_from_bytes(events, events_size);
    lean_object *response = argus_worker_route_check_prepared(handle->value, request);
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

__attribute__((visibility("default"))) void argus_worker_route_free_prepared(
    void *opaque
) {
    struct argus_prepared_route *handle = opaque;
    if (handle == NULL) {
        return;
    }
    pthread_mutex_lock(&argus_lock);
    if (handle->value != NULL) {
        lean_dec_ref(handle->value);
        handle->value = NULL;
    }
    pthread_mutex_unlock(&argus_lock);
    free(handle);
}
