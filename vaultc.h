/*
 * vaultc.h - Interface C para a libvault (abedra/libvault, C++17)
 *
 * Este cabecalho e' o UNICO ponto de contato entre o seu codigo C
 * (compilado no Visual Studio 2010) e a DLL vaultc.dll (compilada com uma
 * toolchain moderna, junto com libvault + libcurl).
 *
 * Regras de compatibilidade:
 *   - Sintaxe restrita ao subconjunto C89/C99 aceito pelo compilador C do
 *     VS2010: sem <stdbool.h>, sem _Bool, sem inline, sem VLAs, sem
 *     inicializadores designados, comentarios apenas no estilo C.
 *   - Nenhum tipo C++ cruza a fronteira da DLL (nada de std::string, STL,
 *     excecoes, etc.). So' ponteiros opacos, int, size_t e const char*.
 *   - Convencao de chamada explicita: __cdecl.
 *   - Toda memoria devolvida pela DLL deve ser liberada pela DLL
 *     (vault_free / vault_free_secret / vault_*_free). NUNCA use free()
 *     do seu executavel: o heap da CRT do VS2010 e' diferente do da DLL.
 *   - Todas as strings sao UTF-8 terminadas em NUL.
 *
 * Thread-safety: um vault_client_t NAO deve ser usado por duas threads ao
 * mesmo tempo. Use um cliente por thread ou serialize o acesso. O texto de
 * erro (vault_last_error) e' por thread.
 */
#ifndef VAULTC_H
#define VAULTC_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Exportacao / convencao de chamada                                   */
/* ------------------------------------------------------------------ */
#if defined(_WIN32)
#  if defined(VAULTC_BUILD_DLL)
#    define VAULTC_API __declspec(dllexport)
#  else
#    define VAULTC_API __declspec(dllimport)
#  endif
#  define VAULTC_CALL __cdecl
#else
#  define VAULTC_API __attribute__((visibility("default")))
#  define VAULTC_CALL
#endif

/* Incrementado a cada mudanca incompativel de ABI. Compare em runtime com
 * vault_abi_version() para detectar DLL/cabecalho dessincronizados. */
#define VAULT_ABI_VERSION 1

/* ------------------------------------------------------------------ */
/* Codigos de retorno                                                  */
/* ------------------------------------------------------------------ */
typedef enum vault_status_e {
    VAULT_OK            = 0,
    VAULT_ERR_INVALID_ARG = 1,  /* ponteiro NULL, struct_size invalido...   */
    VAULT_ERR_NOMEM     = 2,
    VAULT_ERR_AUTH      = 3,    /* autenticacao recusada / sem token        */
    VAULT_ERR_REQUEST   = 4,    /* falha HTTP, resposta vazia ou Vault erro */
    VAULT_ERR_NOT_FOUND = 5,    /* chave pedida nao existe no JSON          */
    VAULT_ERR_PARSE     = 6,    /* resposta do Vault nao e' JSON esperado   */
    VAULT_ERR_EXCEPTION = 7     /* excecao C++ capturada dentro da DLL      */
} vault_status_t;

/* ------------------------------------------------------------------ */
/* Tipos                                                               */
/* ------------------------------------------------------------------ */
typedef struct vault_client_s  vault_client_t;   /* opaco */
typedef struct vault_kv_s      vault_kv_t;       /* opaco */
typedef struct vault_strlist_s vault_strlist_t;  /* opaco */

/* Par chave/valor (equivale a Vault::Parameters). */
typedef struct vault_kv_pair_s {
    const char *key;
    const char *value;
} vault_kv_pair_t;

/* Configuracao de conexao. SEMPRE inicialize com vault_config_init(). */
typedef struct vault_config_s {
    size_t       struct_size;  /* preenchido por vault_config_init()       */
    const char  *host;         /* default "localhost"                      */
    unsigned int port;         /* default 8200                             */
    int          tls_enabled;  /* default 1 (https)                        */
    int          tls_verify;   /* default 1 (valida certificado)           */
    int          debug;        /* default 0                                */
} vault_config_t;

typedef enum vault_kv_version_e {
    VAULT_KV_V1 = 1,
    VAULT_KV_V2 = 2
} vault_kv_version_t;

/* ------------------------------------------------------------------ */
/* Utilitarios gerais                                                  */
/* ------------------------------------------------------------------ */
VAULTC_API int         VAULTC_CALL vault_abi_version(void);
VAULTC_API const char *VAULTC_CALL vault_version(void);
VAULTC_API const char *VAULTC_CALL vault_status_string(vault_status_t status);

/* Ultima mensagem de erro detalhada NESTA thread (nunca NULL).
 * Valida ate' a proxima chamada vaultc na mesma thread; nao libere. */
VAULTC_API const char *VAULTC_CALL vault_last_error(void);

/* Libera memoria devolvida pela DLL (char*, unsigned char*...). NULL ok. */
VAULTC_API void VAULTC_CALL vault_free(void *p);

/* Igual a vault_free, mas zera a string antes (use para tokens/segredos). */
VAULTC_API void VAULTC_CALL vault_free_secret(char *s);

/* ------------------------------------------------------------------ */
/* Configuracao e cliente                                              */
/* ------------------------------------------------------------------ */
VAULTC_API void VAULTC_CALL vault_config_init(vault_config_t *cfg);

/* Cria cliente autenticado por token. */
VAULTC_API vault_status_t VAULTC_CALL
vault_client_new_token(const vault_config_t *cfg,
                       const char *token,
                       vault_client_t **out_client);

/* Cria cliente autenticado por AppRole (role_id + secret_id). */
VAULTC_API vault_status_t VAULTC_CALL
vault_client_new_approle(const vault_config_t *cfg,
                         const char *role_id,
                         const char *secret_id,
                         vault_client_t **out_client);

/* Destroi o cliente. Libere antes todos os vault_kv_t criados a partir dele. */
VAULTC_API void VAULTC_CALL vault_client_free(vault_client_t *client);

/* Retorna 1 se o cliente possui token valido, 0 caso contrario. */
VAULTC_API int VAULTC_CALL vault_client_is_authenticated(const vault_client_t *client);

/* ------------------------------------------------------------------ */
/* Lista de strings (resultado de list)                                */
/* ------------------------------------------------------------------ */
VAULTC_API size_t      VAULTC_CALL vault_strlist_count(const vault_strlist_t *list);
VAULTC_API const char *VAULTC_CALL vault_strlist_get(const vault_strlist_t *list, size_t index);
VAULTC_API void        VAULTC_CALL vault_strlist_free(vault_strlist_t *list);

/* ------------------------------------------------------------------ */
/* Key/Value (v1 e v2)                                                 */
/* ------------------------------------------------------------------ */

/* mount: ponto de montagem da engine KV, ex.: "secret". */
VAULTC_API vault_status_t VAULTC_CALL
vault_kv_new(vault_client_t *client,
             const char *mount,
             vault_kv_version_t version,
             vault_kv_t **out_kv);

VAULTC_API void VAULTC_CALL vault_kv_free(vault_kv_t *kv);

/* Le o segredo e devolve o JSON bruto da resposta do Vault
 * (libere com vault_free_secret). */
VAULTC_API vault_status_t VAULTC_CALL
vault_kv_read(vault_kv_t *kv, const char *path, char **out_json);

/* Atalho: le o segredo e devolve apenas o valor de um campo.
 * Valores nao-string sao devolvidos serializados em JSON.
 * Retorna VAULT_ERR_NOT_FOUND se o campo nao existir.
 * (libere com vault_free_secret). */
VAULTC_API vault_status_t VAULTC_CALL
vault_kv_read_value(vault_kv_t *kv, const char *path,
                    const char *field, char **out_value);

VAULTC_API vault_status_t VAULTC_CALL
vault_kv_create(vault_kv_t *kv, const char *path,
                const vault_kv_pair_t *pairs, size_t count);

VAULTC_API vault_status_t VAULTC_CALL
vault_kv_update(vault_kv_t *kv, const char *path,
                const vault_kv_pair_t *pairs, size_t count);

VAULTC_API vault_status_t VAULTC_CALL
vault_kv_delete(vault_kv_t *kv, const char *path);

/* Lista as chaves sob "path". Libere com vault_strlist_free. */
VAULTC_API vault_status_t VAULTC_CALL
vault_kv_list(vault_kv_t *kv, const char *path, vault_strlist_t **out_list);

/* ------------------------------------------------------------------ */
/* Transit (engine montada em "transit")                               */
/* Dados binarios sao aceitos; a codificacao base64 e' feita na DLL.   */
/* ------------------------------------------------------------------ */

/* key_type pode ser NULL (default do Vault, aes256-gcm96). */
VAULTC_API vault_status_t VAULTC_CALL
vault_transit_create_key(vault_client_t *client,
                         const char *key_name,
                         const char *key_type);

VAULTC_API vault_status_t VAULTC_CALL
vault_transit_rotate_key(vault_client_t *client, const char *key_name);

/* Devolve o ciphertext ("vault:v1:...") em out_ciphertext (vault_free). */
VAULTC_API vault_status_t VAULTC_CALL
vault_transit_encrypt(vault_client_t *client,
                      const char *key_name,
                      const void *data, size_t data_len,
                      char **out_ciphertext);

/* Devolve o texto claro em out_data/out_len. Um NUL extra e' anexado
 * (nao contado em out_len) para facilitar o uso como string.
 * Libere com vault_free_secret((char*)*out_data). */
VAULTC_API vault_status_t VAULTC_CALL
vault_transit_decrypt(vault_client_t *client,
                      const char *key_name,
                      const char *ciphertext,
                      unsigned char **out_data, size_t *out_len);

/* ------------------------------------------------------------------ */
/* Sys / mounts                                                        */
/* ------------------------------------------------------------------ */

/* Lista as engines montadas (JSON bruto; libere com vault_free). */
VAULTC_API vault_status_t VAULTC_CALL
vault_sys_mounts_list(vault_client_t *client, char **out_json);

/* Monta uma engine. type: "kv", "transit", ... options: pares extras
 * (ex.: "description"), pode ser NULL com count 0. */
VAULTC_API vault_status_t VAULTC_CALL
vault_sys_mounts_enable(vault_client_t *client,
                        const char *path, const char *type,
                        const vault_kv_pair_t *options, size_t count);

VAULTC_API vault_status_t VAULTC_CALL
vault_sys_mounts_disable(vault_client_t *client, const char *path);

#ifdef __cplusplus
}
#endif

#endif /* VAULTC_H */
