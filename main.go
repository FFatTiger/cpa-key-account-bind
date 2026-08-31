// Package main implements a CLIProxyAPI native plugin (C ABI, dlopen) that
// binds downstream API keys to specific upstream credentials (auth files).
//
// # Isolation model
//
// Downstream authentication stays with CPA's native api-keys: a key that is
// not in config api-keys is rejected by the host before scheduling. This
// plugin hooks ONLY into scheduler.pick: when the host asks which credential
// should serve a request, the plugin extracts the downstream key from the
// original request headers (forwarded by the host as Options.Headers) and
// restricts the candidate set to the auth IDs allowed for that key.
//
// Guarantees
//
//   - A bound key can only ever land on an allowed auth ID: if no allowed
//     candidate is available the plugin returns an error envelope and the
//     host fails the request (never falls back to another credential).
//   - Unbound keys are left to the host scheduler (passthrough) or rejected
//     (deny), per config.
//
// Why not FrontendAuthProvider: the host does not forward frontend-auth
// metadata into scheduler options (verified on CLIProxyAPI v7.2.146), so a
// metadata-based hand-off silently degrades to full-pool scheduling. This
// plugin closes the loop by resolving the key from headers at pick time.
package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);
*/
import "C"

import (
	"encoding/json"
	"sync/atomic"
	"unsafe"
)

// state holds the currently active policy. Swapped atomically on
// plugin.register / plugin.reconfigure.
var state atomic.Pointer[policy]

// envelope is the wire envelope every method call uses.
type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func okEnvelope(result any) []byte {
	raw, err := json.Marshal(result)
	if err != nil {
		return errorEnvelope("json_error", err.Error())
	}
	env := envelope{OK: true, Result: raw}
	out, err := json.Marshal(env)
	if err != nil {
		return errorEnvelope("json_error", err.Error())
	}
	return out
}

func errorEnvelope(code, message string) []byte {
	env := envelope{Error: &envelopeError{Code: code, Message: message}}
	out, _ := json.Marshal(env)
	return out
}

//export cliproxy_plugin_init
func cliproxy_plugin_init(_ *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	plugin.abi_version = 1
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		return 1
	}
	methodName := C.GoString(method)
	var req []byte
	if request != nil && requestLen > 0 {
		req = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	out := safeCall(methodName, req)
	if len(out) == 0 {
		return 1
	}
	ptr := C.CBytes(out)
	if ptr == nil {
		return 1
	}
	response.ptr = ptr
	response.len = C.size_t(len(out))
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, length C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {}

// safeCall dispatches one method with panic recovery. A plugin panic must
// never take down the host process; we degrade to an error envelope instead
// (the host fails the request rather than scheduling a wrong credential).
func safeCall(method string, req []byte) (out []byte) {
	defer func() {
		if r := recover(); r != nil {
			out = errorEnvelope("plugin_panic", "key-account-bind recovered from panic")
		}
	}()
	return dispatch(method, req)
}

func dispatch(method string, req []byte) []byte {
	switch method {
	case "plugin.register", "plugin.reconfigure":
		return handleConfigure(req)
	case "scheduler.pick":
		return handlePick(req)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method)
	}
}

func main() {} // required for c-shared builds; never runs
