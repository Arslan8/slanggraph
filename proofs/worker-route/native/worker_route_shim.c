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
extern lean_object *argus_worker_route_prepare_grant(lean_object *input);
extern uint8_t argus_worker_route_check_prepared_grant(
    lean_object *prepared,
    lean_object *principal,
    lean_object *session,
    lean_object *tool,
    lean_object *artifact,
    lean_object *call,
    lean_object *intent,
    lean_object *policy,
    lean_object *deployment,
    lean_object *runtime,
    lean_object *digest
);
extern uint8_t argus_worker_route_check_prepared_go(
    lean_object *, lean_object *, lean_object *, lean_object *, lean_object *,
    lean_object *, lean_object *, lean_object *, lean_object *, lean_object *,
    lean_object *, lean_object *, lean_object *, lean_object *, lean_object *,
    lean_object *, lean_object *, lean_object *, uint8_t
);
extern uint8_t argus_worker_route_check_prepared_success(
    lean_object *, lean_object *, lean_object *, lean_object *, lean_object *,
    lean_object *, lean_object *, lean_object *, lean_object *, lean_object *,
    lean_object *, lean_object *, lean_object *, lean_object *, lean_object *,
    lean_object *, lean_object *, lean_object *
);

struct argus_prepared_route {
    lean_object *value;
};

struct argus_slice {
    const char *data;
    size_t size;
};

struct argus_grant_binding {
    struct argus_slice principal;
    struct argus_slice session;
    struct argus_slice tool;
    struct argus_slice artifact;
    struct argus_slice call;
    struct argus_slice intent;
    struct argus_slice policy;
    struct argus_slice deployment;
    struct argus_slice runtime;
    struct argus_slice digest;
};

struct argus_route_binding {
    struct argus_slice principal;
    struct argus_slice session;
    struct argus_slice call;
    struct argus_slice intent;
    struct argus_slice policy;
    struct argus_slice tool;
    struct argus_slice artifact;
    struct argus_slice deployment;
    struct argus_slice runtime;
    struct argus_slice grant;
    struct argus_slice plan;
    struct argus_slice nonce;
    struct argus_slice host;
    struct argus_slice context;
    struct argus_slice worker_pid;
    struct argus_slice worker_start_time;
    struct argus_slice worker_boot_id;
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

/* Parse and prove the complete grant inventory once during preparation. */
__attribute__((visibility("default"))) void *argus_worker_route_prepare_grant_json(
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
    lean_object *result = argus_worker_route_prepare_grant(request);
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

static int argus_valid_slice(const struct argus_slice *value) {
    return value != NULL && (value->data != NULL || value->size == 0);
}

static lean_object *argus_slice_string(const struct argus_slice *value) {
    const char *data = value->data == NULL ? "" : value->data;
    return lean_mk_string_from_bytes(data, value->size);
}

static int argus_valid_route_binding(const struct argus_route_binding *binding) {
    return binding != NULL &&
        argus_valid_slice(&binding->principal) &&
        argus_valid_slice(&binding->session) &&
        argus_valid_slice(&binding->call) &&
        argus_valid_slice(&binding->intent) &&
        argus_valid_slice(&binding->policy) &&
        argus_valid_slice(&binding->tool) &&
        argus_valid_slice(&binding->artifact) &&
        argus_valid_slice(&binding->deployment) &&
        argus_valid_slice(&binding->runtime) &&
        argus_valid_slice(&binding->grant) &&
        argus_valid_slice(&binding->plan) &&
        argus_valid_slice(&binding->nonce) &&
        argus_valid_slice(&binding->host) &&
        argus_valid_slice(&binding->context) &&
        argus_valid_slice(&binding->worker_pid) &&
        argus_valid_slice(&binding->worker_start_time) &&
        argus_valid_slice(&binding->worker_boot_id);
}

/* Apply one of the two useful lifecycle transitions to the retained Lean
 * certificate. The bridge transports facts; Lean still decides the phase. */
__attribute__((visibility("default"))) int argus_worker_route_check_prepared_go_typed(
    void *opaque,
    const struct argus_route_binding *binding,
    int supported
) {
    struct argus_prepared_route *handle = opaque;
    if (handle == NULL || handle->value == NULL ||
        !argus_valid_route_binding(binding) || (supported != 0 && supported != 1)) {
        return -1;
    }
    pthread_once(&argus_once, argus_initialize);
    if (!argus_initialized) {
        return -3;
    }
    pthread_mutex_lock(&argus_lock);
    lean_inc(handle->value);
    uint8_t accepted = argus_worker_route_check_prepared_go(
        handle->value,
        argus_slice_string(&binding->principal),
        argus_slice_string(&binding->session),
        argus_slice_string(&binding->call),
        argus_slice_string(&binding->intent),
        argus_slice_string(&binding->policy),
        argus_slice_string(&binding->tool),
        argus_slice_string(&binding->artifact),
        argus_slice_string(&binding->deployment),
        argus_slice_string(&binding->runtime),
        argus_slice_string(&binding->grant),
        argus_slice_string(&binding->plan),
        argus_slice_string(&binding->nonce),
        argus_slice_string(&binding->host),
        argus_slice_string(&binding->context),
        argus_slice_string(&binding->worker_pid),
        argus_slice_string(&binding->worker_start_time),
        argus_slice_string(&binding->worker_boot_id),
        (uint8_t)supported
    );
    pthread_mutex_unlock(&argus_lock);
    return accepted == 1 ? 1 : 0;
}

__attribute__((visibility("default"))) int argus_worker_route_check_prepared_success_typed(
    void *opaque,
    const struct argus_route_binding *binding
) {
    struct argus_prepared_route *handle = opaque;
    if (handle == NULL || handle->value == NULL || !argus_valid_route_binding(binding)) {
        return -1;
    }
    pthread_once(&argus_once, argus_initialize);
    if (!argus_initialized) {
        return -3;
    }
    pthread_mutex_lock(&argus_lock);
    lean_inc(handle->value);
    uint8_t accepted = argus_worker_route_check_prepared_success(
        handle->value,
        argus_slice_string(&binding->principal),
        argus_slice_string(&binding->session),
        argus_slice_string(&binding->call),
        argus_slice_string(&binding->intent),
        argus_slice_string(&binding->policy),
        argus_slice_string(&binding->tool),
        argus_slice_string(&binding->artifact),
        argus_slice_string(&binding->deployment),
        argus_slice_string(&binding->runtime),
        argus_slice_string(&binding->grant),
        argus_slice_string(&binding->plan),
        argus_slice_string(&binding->nonce),
        argus_slice_string(&binding->host),
        argus_slice_string(&binding->context),
        argus_slice_string(&binding->worker_pid),
        argus_slice_string(&binding->worker_start_time),
        argus_slice_string(&binding->worker_boot_id)
    );
    pthread_mutex_unlock(&argus_lock);
    return accepted == 1 ? 1 : 0;
}

/* Bind fresh invocation fields without JSON construction or parsing. */
__attribute__((visibility("default"))) int argus_worker_route_check_prepared_grant_typed(
    void *opaque,
    const struct argus_grant_binding *binding
) {
    struct argus_prepared_route *handle = opaque;
    if (handle == NULL || handle->value == NULL || binding == NULL ||
        !argus_valid_slice(&binding->principal) ||
        !argus_valid_slice(&binding->session) ||
        !argus_valid_slice(&binding->tool) ||
        !argus_valid_slice(&binding->artifact) ||
        !argus_valid_slice(&binding->call) ||
        !argus_valid_slice(&binding->intent) ||
        !argus_valid_slice(&binding->policy) ||
        !argus_valid_slice(&binding->deployment) ||
        !argus_valid_slice(&binding->runtime) ||
        !argus_valid_slice(&binding->digest)) {
        return -1;
    }
    pthread_once(&argus_once, argus_initialize);
    if (!argus_initialized) {
        return -3;
    }
    pthread_mutex_lock(&argus_lock);
    lean_inc(handle->value);
    uint8_t accepted = argus_worker_route_check_prepared_grant(
        handle->value,
        argus_slice_string(&binding->principal),
        argus_slice_string(&binding->session),
        argus_slice_string(&binding->tool),
        argus_slice_string(&binding->artifact),
        argus_slice_string(&binding->call),
        argus_slice_string(&binding->intent),
        argus_slice_string(&binding->policy),
        argus_slice_string(&binding->deployment),
        argus_slice_string(&binding->runtime),
        argus_slice_string(&binding->digest)
    );
    pthread_mutex_unlock(&argus_lock);
    return accepted == 1 ? 1 : 0;
}

__attribute__((visibility("default"))) void argus_worker_route_free_prepared_grant(
    void *opaque
) {
    argus_worker_route_free_prepared(opaque);
}
