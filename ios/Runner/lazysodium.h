#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
typedef struct _Dart_Handle* Dart_Handle;

#define CRYPTO_KX_PK_BYTES (uintptr_t)crypto_kx_PUBLICKEYBYTES

#define CRYPTO_KX_SK_BYTES (uintptr_t)crypto_kx_SECRETKEYBYTES

#define CRYPTO_KX_PK_HEX (CRYPTO_KX_PK_BYTES * 2)

#define CRYPTO_KX_SK_HEX (CRYPTO_KX_SK_BYTES * 2)

#define CRYPTO_KX_SESSION_KEY_BYTES (uintptr_t)crypto_kx_SESSIONKEYBYTES

#define CRYPTO_KX_SECRET_KEY_BYTES (uintptr_t)crypto_kx_SECRETKEYBYTES

#define CRYPTO_BOX_PK_KEY_BYTES (uintptr_t)crypto_box_PUBLICKEYBYTES

#define CRYPTO_BOX_SK_KEY_BYTES (uintptr_t)crypto_box_SECRETKEYBYTES

#define CRYPTO_AEAD_CHACHA20POLY1305_KEY_BYTES (uintptr_t)crypto_aead_chacha20poly1305_KEYBYTES

#define CRYPTO_AEAD_CHACHA20POLY1305_ABYTES (uintptr_t)crypto_aead_chacha20poly1305_ABYTES

#define CRYPTO_AEAD_CHACHA20POLY1305_NSEC_BYTES (uintptr_t)crypto_aead_chacha20poly1305_NSECBYTES

#define CRYPTO_AEAD_CHACHA20POLY1305_NPUB_BYTES (uintptr_t)crypto_aead_chacha20poly1305_NPUBBYTES

#define CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEY_BYTES (uintptr_t)crypto_aead_chacha20poly1305_ietf_KEYBYTES

#define CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEY_BYTES (uintptr_t)crypto_aead_xchacha20poly1305_ietf_KEYBYTES

#define CRYPTO_STREAM_XSALSA20_KEY_BYTES (uintptr_t)crypto_stream_xsalsa20_KEYBYTES

#define CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PK_BYTES (uintptr_t)crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES

#define CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SK_BYTES (uintptr_t)crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES

#define CRYPTO_NONCE_BYTES 24

#define CRYPTO_NONCE_HEX 48

#define CRYPTO_BOX_BEFORE_NM_BYTES (uintptr_t)crypto_box_BEFORENMBYTES

#define CRYPTO_SECRET_BOX_NONCE_BYTES (uintptr_t)crypto_secretbox_NONCEBYTES

#define CRYPTO_SECRETBOX_KEY_BYTES (uintptr_t)crypto_secretbox_KEYBYTES

#define CRYPTO_STREAM_CHACHA20_KEY_BYTES (uintptr_t)crypto_stream_chacha20_KEYBYTES

#define CRYPTO_STREAM_CHACHA20_NONCE_BYTES (uintptr_t)crypto_stream_chacha20_NONCEBYTES

#define CRYPTO_STREAM_CHACHA20_IETF_KEY_BYTES (uintptr_t)crypto_stream_chacha20_ietf_KEYBYTES

#define CRYPTO_STREAM_CHACHA20_IETF_NONCE_BYTES (uintptr_t)crypto_stream_chacha20_ietf_NONCEBYTES

#define CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEY_BYTES (uintptr_t)crypto_secretstream_xchacha20poly1305_KEYBYTES

#define CRYPTO_STREAM_KEY_BYTES (uintptr_t)crypto_stream_KEYBYTES

#define CRYPTO_STREAM_NONCE_BYTES (uintptr_t)crypto_stream_NONCEBYTES

#define CRYPTO_STREAM_XCHACHA20_KEY_BYTES (uintptr_t)crypto_stream_xchacha20_KEYBYTES

#define CRYPTO_STREAM_XCHACHA20_NONCE_BYTES (uintptr_t)crypto_stream_xchacha20_NONCEBYTES

#define CRYPTO_SECRETBOX_XCHACHA20POLY1305_KEY_BYTES (uintptr_t)crypto_secretbox_xchacha20poly1305_KEYBYTES

#define CRYPTO_SECRETBOX_XCHACHA20POLY1305_NONCE_BYTES (uintptr_t)crypto_secretbox_xchacha20poly1305_NONCEBYTES

#define CRYPTO_SECRETBOX_XCHACHA20POLY1305_MAC_BYTES (uintptr_t)crypto_secretbox_xchacha20poly1305_MACBYTES

typedef struct DartCObject DartCObject;

typedef int64_t DartPort;

typedef bool (*DartPostCObjectFnType)(DartPort port_id, void *message);

typedef struct wire_uint_8_list {
  uint8_t *ptr;
  int32_t len;
} wire_uint_8_list;

typedef struct wire_KeyPair {
  struct wire_uint_8_list *pk;
  struct wire_uint_8_list *sk;
} wire_KeyPair;

typedef struct DartCObject *WireSyncReturn;

void store_dart_post_cobject(DartPostCObjectFnType ptr);

Dart_Handle get_dart_object(uintptr_t ptr);

void drop_dart_object(uintptr_t ptr);

uintptr_t new_dart_opaque(Dart_Handle handle);

intptr_t init_frb_dart_api_dl(void *obj);

void wire_crypto_kx_keypair(int64_t port_, uintptr_t pk_size, uintptr_t sk_size);

void wire_crypto_box_beforenm(int64_t port_, struct wire_KeyPair *keypair);

void wire_crypto_box_beforenm_hex(int64_t port_, struct wire_KeyPair *keypair);

void wire_crypto_kx_client_session_keys(int64_t port_,
                                        struct wire_uint_8_list *client_pk,
                                        struct wire_uint_8_list *client_sk,
                                        struct wire_uint_8_list *server_pk);

void wire_crypto_kx_server_session_keys(int64_t port_,
                                        struct wire_uint_8_list *server_pk,
                                        struct wire_uint_8_list *server_sk,
                                        struct wire_uint_8_list *client_pk);

void wire_crypto_stream_chacha20_xor(int64_t port_,
                                     struct wire_uint_8_list *message,
                                     struct wire_uint_8_list *nonce,
                                     struct wire_uint_8_list *key);

void wire_crypto_aead_chacha20poly1305_encrypt(int64_t port_,
                                               struct wire_uint_8_list *message,
                                               struct wire_uint_8_list *nonce,
                                               struct wire_uint_8_list *key,
                                               struct wire_uint_8_list *additional_data);

void wire_crypto_aead_chacha20poly1305_decrypt(int64_t port_,
                                               struct wire_uint_8_list *ciphertext,
                                               struct wire_uint_8_list *nonce,
                                               struct wire_uint_8_list *key,
                                               struct wire_uint_8_list *additional_data);

void wire_bin_to_hex(int64_t port_, struct wire_uint_8_list *data);

void wire_crypto_secretbox_xchacha20poly1305_easy(int64_t port_,
                                                  struct wire_uint_8_list *message,
                                                  struct wire_uint_8_list *nonce,
                                                  struct wire_uint_8_list *key);

void wire_hex_to_bin(int64_t port_, struct wire_uint_8_list *hex);

void wire_random_bytes_buf(int64_t port_, uintptr_t size);

void wire_random_nonce_bytes(int64_t port_);

void wire_random_nonce_hex(int64_t port_);

struct wire_KeyPair *new_box_autoadd_key_pair_0(void);

struct wire_uint_8_list *new_uint_8_list_0(int32_t len);

void free_WireSyncReturn(WireSyncReturn ptr);

static int64_t dummy_method_to_enforce_bundling(void) {
    int64_t dummy_var = 0;
    dummy_var ^= ((int64_t) (void*) wire_crypto_kx_keypair);
    dummy_var ^= ((int64_t) (void*) wire_crypto_box_beforenm);
    dummy_var ^= ((int64_t) (void*) wire_crypto_box_beforenm_hex);
    dummy_var ^= ((int64_t) (void*) wire_crypto_kx_client_session_keys);
    dummy_var ^= ((int64_t) (void*) wire_crypto_kx_server_session_keys);
    dummy_var ^= ((int64_t) (void*) wire_crypto_stream_chacha20_xor);
    dummy_var ^= ((int64_t) (void*) wire_crypto_aead_chacha20poly1305_encrypt);
    dummy_var ^= ((int64_t) (void*) wire_crypto_aead_chacha20poly1305_decrypt);
    dummy_var ^= ((int64_t) (void*) wire_bin_to_hex);
    dummy_var ^= ((int64_t) (void*) wire_crypto_secretbox_xchacha20poly1305_easy);
    dummy_var ^= ((int64_t) (void*) wire_hex_to_bin);
    dummy_var ^= ((int64_t) (void*) wire_random_bytes_buf);
    dummy_var ^= ((int64_t) (void*) wire_random_nonce_bytes);
    dummy_var ^= ((int64_t) (void*) wire_random_nonce_hex);
    dummy_var ^= ((int64_t) (void*) new_box_autoadd_key_pair_0);
    dummy_var ^= ((int64_t) (void*) new_uint_8_list_0);
    dummy_var ^= ((int64_t) (void*) free_WireSyncReturn);
    dummy_var ^= ((int64_t) (void*) store_dart_post_cobject);
    dummy_var ^= ((int64_t) (void*) get_dart_object);
    dummy_var ^= ((int64_t) (void*) drop_dart_object);
    dummy_var ^= ((int64_t) (void*) new_dart_opaque);
    return dummy_var;
}
