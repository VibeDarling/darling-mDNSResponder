#!/usr/bin/env python3
"""Compile actual resolver-default bodies against a host XPC ownership mock.

This checks cleanup and locking behavior without a Darling SDK. It is not a
full mDNSResponder build or a DNS/network integration test.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
apple = (root / 'mDNSShared/dnssd_clientstub_apple.c').read_text()
body = apple[apple.index('static xpc_object_t'):]
client = (root / 'mDNSShared/dnssd_clientstub.c').read_text()
cleanups = re.findall(r'if \(defaults\) xpc_release\(defaults\);\s*defaults = NULL;', client)
assert len(cleanups) == 4, 'Expected cleanup in both error/success paths of both APIs'
wrappers = '\n'.join('static void cleanup%d(xpc_object_t *value) { xpc_object_t defaults = *value; %s *value = defaults; }' % (i, code) for i, code in enumerate(cleanups))
mock = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
typedef struct { atomic_int refs; bool privacy; size_t length; unsigned char data[8]; } *xpc_object_t;
typedef int DNSServiceErrorType;
#define DNSSD_API
#define kDNSServiceErr_Invalid -65549
#define kDNSServiceErr_NoMemory -65539
#define kDNSServiceErr_NoError 0
#define CUBytesPerKibiByte 1024
#define kDNSServiceDefaultsKey_RequirePrivacy "require_privacy"
#define kDNSServiceDefaultsKey_ResolverConfigPListData "resolver_config_plist_data"
#define require_action_quiet(test, label, action) do { if (!(test)) { action; goto label; } } while (0)
typedef pthread_mutex_t os_unfair_lock;
#define OS_UNFAIR_LOCK_INIT PTHREAD_MUTEX_INITIALIZER
static _Thread_local int lock_depth;
static atomic_int allocated, freed;
static bool fail_allocation;
static void os_unfair_lock_lock(os_unfair_lock *lock) { pthread_mutex_lock(lock); ++lock_depth; }
static void os_unfair_lock_unlock(os_unfair_lock *lock) { --lock_depth; pthread_mutex_unlock(lock); }
static xpc_object_t xpc_dictionary_create(void *keys, void *values, size_t count) {
    (void)keys; (void)values; (void)count;
    if (fail_allocation) return NULL;
    xpc_object_t result = calloc(1, sizeof(*result)); assert(result);
    atomic_init(&result->refs, 1); ++allocated; return result;
}
static void xpc_dictionary_set_bool(xpc_object_t object, const char *key, bool value) { (void)key; object->privacy = value; }
static void xpc_dictionary_set_data(xpc_object_t object, const char *key, const void *bytes, size_t size) {
    (void)key; assert(size <= sizeof(object->data)); object->length = size; memcpy(object->data, bytes, size);
}
static xpc_object_t xpc_retain(xpc_object_t object) { assert(object); ++object->refs; return object; }
static void xpc_release(xpc_object_t object) {
    assert(object); assert(lock_depth == 0);
    if (atomic_fetch_sub(&object->refs, 1) == 1) { ++freed; free(object); }
}
'''
test = r'''
static void *concurrent_defaults(void *unused) {
    (void)unused;
    for (int i = 0; i < 1000; ++i) {
        assert(DNSServiceSetResolverDefaults(NULL, 0, i % 2) == 0);
        xpc_object_t value = DNSServiceGetRetainedResolverDefaults();
        assert(value); xpc_release(value);
    }
    return NULL;
}
int main(void) {
    assert(DNSServiceGetRetainedResolverDefaults() == NULL);
    unsigned char data[] = {1, 2, 3};
    assert(DNSServiceSetResolverDefaults(data, sizeof(data), true) == 0);
    xpc_object_t old = DNSServiceGetRetainedResolverDefaults();
    assert(old->privacy && old->length == 3 && !memcmp(old->data, data, 3));
    assert(atomic_load(&old->refs) == 2);
    assert(DNSServiceSetResolverDefaults(NULL, 0, false) == 0);
    assert(atomic_load(&old->refs) == 1); xpc_release(old);
    xpc_object_t current = DNSServiceGetRetainedResolverDefaults();
    assert(!current->privacy && current->length == 0);
    int count = atomic_load(&allocated);
    assert(DNSServiceSetResolverDefaults(NULL, 32769, false) == kDNSServiceErr_Invalid);
    assert(atomic_load(&allocated) == count);
    fail_allocation = true;
    assert(DNSServiceSetResolverDefaults(NULL, 0, true) == kDNSServiceErr_NoMemory);
    fail_allocation = false;
    xpc_object_t unchanged = DNSServiceGetRetainedResolverDefaults();
    assert(unchanged == current); xpc_release(unchanged); xpc_release(current);
    void (*cleanups[])(xpc_object_t *) = {cleanup0, cleanup1, cleanup2, cleanup3};
    for (int i = 0; i < 4; ++i) {
        xpc_object_t value = NULL; cleanups[i](&value); assert(!value);
        value = xpc_dictionary_create(NULL, NULL, 0);
        int releases = atomic_load(&freed); cleanups[i](&value);
        assert(!value && atomic_load(&freed) == releases + 1);
    }
    pthread_t threads[4];
    for (int i = 0; i < 4; ++i) assert(!pthread_create(&threads[i], NULL, concurrent_defaults, NULL));
    for (int i = 0; i < 4; ++i) assert(!pthread_join(threads[i], NULL));
    xpc_release(g_defaults_dict); g_defaults_dict = NULL;
    assert(atomic_load(&allocated) == atomic_load(&freed));
    puts("PASS: resolver defaults, failure paths, four cleanup paths, 4000 concurrent replacements; no leaked mock references");
}
'''
with tempfile.TemporaryDirectory(prefix='dnssd-xpc-test-') as temporary:
    source = Path(temporary) / 'test.c'
    source.write_text(mock + body + wrappers + test)
    executable = Path(temporary) / 'test'
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror', '-pthread', '-O2', str(source), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=15)
