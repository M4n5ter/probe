#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdlib.h>

#define TRAFFIC_PROBE_E2E_REAL_TLS_ENGINE_ENV "TRAFFIC_PROBE_E2E_REAL_TLS_ENGINE_PATH"

typedef const void *(*TLS_client_method_fn)(void);
typedef void *(*SSL_CTX_new_fn)(const void *);
typedef void (*SSL_CTX_free_fn)(void *);
typedef void *(*SSL_new_fn)(void *);
typedef void (*SSL_free_fn)(void *);
typedef int (*SSL_set_fd_fn)(void *, int);
typedef int (*SSL_connect_fn)(void *);
typedef int (*SSL_write_ex_fn)(void *, const void *, size_t, size_t *);
typedef int (*SSL_shutdown_fn)(void *);

static void *real_libssl;

static void *real_symbol(const char *name) {
    if (real_libssl == NULL) {
        const char *path = getenv(TRAFFIC_PROBE_E2E_REAL_TLS_ENGINE_ENV);
        if (path == NULL || path[0] == '\0') {
            return NULL;
        }
        real_libssl = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    }
    if (real_libssl == NULL) {
        return NULL;
    }
    return dlsym(real_libssl, name);
}

const void *TLS_client_method(void) {
    TLS_client_method_fn fn = (TLS_client_method_fn)real_symbol("TLS_client_method");
    return fn == NULL ? NULL : fn();
}

void *SSL_CTX_new(const void *method) {
    SSL_CTX_new_fn fn = (SSL_CTX_new_fn)real_symbol("SSL_CTX_new");
    return fn == NULL ? NULL : fn(method);
}

void SSL_CTX_free(void *ctx) {
    SSL_CTX_free_fn fn = (SSL_CTX_free_fn)real_symbol("SSL_CTX_free");
    if (fn != NULL) {
        fn(ctx);
    }
}

void *SSL_new(void *ctx) {
    SSL_new_fn fn = (SSL_new_fn)real_symbol("SSL_new");
    return fn == NULL ? NULL : fn(ctx);
}

void SSL_free(void *ssl) {
    SSL_free_fn fn = (SSL_free_fn)real_symbol("SSL_free");
    if (fn != NULL) {
        fn(ssl);
    }
}

int SSL_set_fd(void *ssl, int fd) {
    SSL_set_fd_fn fn = (SSL_set_fd_fn)real_symbol("SSL_set_fd");
    return fn == NULL ? 0 : fn(ssl, fd);
}

int SSL_connect(void *ssl) {
    SSL_connect_fn fn = (SSL_connect_fn)real_symbol("SSL_connect");
    return fn == NULL ? -1 : fn(ssl);
}

int SSL_write_ex(void *ssl, const void *buf, size_t num, size_t *written) {
    SSL_write_ex_fn fn = (SSL_write_ex_fn)real_symbol("SSL_write_ex");
    return fn == NULL ? 0 : fn(ssl, buf, num, written);
}

int SSL_shutdown(void *ssl) {
    SSL_shutdown_fn fn = (SSL_shutdown_fn)real_symbol("SSL_shutdown");
    return fn == NULL ? -1 : fn(ssl);
}
