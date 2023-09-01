#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
typedef struct _Dart_Handle* Dart_Handle;

#define KX_PK_BYTES (uintptr_t)crypto_kx_PUBLICKEYBYTES

#define KX_SK_BYTES (uintptr_t)crypto_kx_SECRETKEYBYTES

#define KX_PK_HEX_BYTES (KX_PK_BYTES * 2)

#define KX_SK_HEX_BYTES (KX_SK_BYTES * 2)

typedef struct DartCObject DartCObject;

typedef int64_t DartPort;

typedef bool (*DartPostCObjectFnType)(DartPort port_id, void *message);

typedef struct wire_uint_8_list {
  uint8_t *ptr;
  int32_t len;
} wire_uint_8_list;

typedef struct DartCObject *WireSyncReturn;

void store_dart_post_cobject(DartPostCObjectFnType ptr);

Dart_Handle get_dart_object(uintptr_t ptr);

void drop_dart_object(uintptr_t ptr);

uintptr_t new_dart_opaque(Dart_Handle handle);

intptr_t init_frb_dart_api_dl(void *obj);

void wire_gen_keypair(int64_t port_);

void wire_bin_to_hex(int64_t port_, struct wire_uint_8_list *data);

void wire_hex_to_bin(int64_t port_, struct wire_uint_8_list *hex);

struct wire_uint_8_list *new_uint_8_list_0(int32_t len);

void free_WireSyncReturn(WireSyncReturn ptr);

static int64_t dummy_method_to_enforce_bundling(void) {
    int64_t dummy_var = 0;
    dummy_var ^= ((int64_t) (void*) wire_gen_keypair);
    dummy_var ^= ((int64_t) (void*) wire_bin_to_hex);
    dummy_var ^= ((int64_t) (void*) wire_hex_to_bin);
    dummy_var ^= ((int64_t) (void*) new_uint_8_list_0);
    dummy_var ^= ((int64_t) (void*) free_WireSyncReturn);
    dummy_var ^= ((int64_t) (void*) store_dart_post_cobject);
    dummy_var ^= ((int64_t) (void*) get_dart_object);
    dummy_var ^= ((int64_t) (void*) drop_dart_object);
    dummy_var ^= ((int64_t) (void*) new_dart_opaque);
    return dummy_var;
}
