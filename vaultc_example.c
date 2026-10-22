/*
 * vaultc_example.c - Exemplo de uso (compila no Visual Studio 2010, modo C).
 * Declaracoes sempre no topo dos blocos (C89), sem bool, sem VLAs.
 *
 * Uso (Vault em modo dev):
 *   set VAULT_TOKEN=<token>
 *   vaultc_example.exe
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vaultc.h"

static int check(vault_status_t st, const char *what)
{
    if (st != VAULT_OK) {
        printf("[ERRO] %s: %s (%s)\n", what,
               vault_status_string(st), vault_last_error());
        return 0;
    }
    return 1;
}

int main(void)
{
    vault_config_t   cfg;
    vault_client_t  *client = NULL;
    vault_kv_t      *kv     = NULL;
    vault_kv_pair_t  pairs[2];
    vault_strlist_t *keys   = NULL;
    char            *json   = NULL;
    char            *value  = NULL;
    char            *ct     = NULL;
    unsigned char   *plain  = NULL;
    size_t           plain_len = 0;
    size_t           i, n;
    const char      *token;
    const char      *msg = "texto confidencial";
    int              rc = 1;

    if (vault_abi_version() != VAULT_ABI_VERSION) {
        printf("vaultc.dll incompativel com vaultc.h (ABI %d != %d)\n",
               vault_abi_version(), VAULT_ABI_VERSION);
        return 2;
    }
    printf("%s\n", vault_version());

    token = getenv("VAULT_TOKEN");
    if (token == NULL) {
        printf("Defina a variavel de ambiente VAULT_TOKEN.\n");
        return 2;
    }

    /* --- cliente --- */
    vault_config_init(&cfg);
    cfg.host        = "127.0.0.1";
    cfg.port        = 8200;
    cfg.tls_enabled = 0;           /* servidor dev sem TLS */

    if (!check(vault_client_new_token(&cfg, token, &client), "login")) goto done;

    /* --- KV v2 em "secret" --- */
    if (!check(vault_kv_new(client, "secret", VAULT_KV_V2, &kv), "kv_new")) goto done;

    pairs[0].key = "usuario"; pairs[0].value = "fabio";
    pairs[1].key = "senha";   pairs[1].value = "s3gredo!";
    if (!check(vault_kv_create(kv, "app/db", pairs, 2), "kv_create")) goto done;

    if (check(vault_kv_read_value(kv, "app/db", "usuario", &value), "kv_read_value")) {
        printf("usuario = %s\n", value);
        vault_free_secret(value);
        value = NULL;
    }

    if (check(vault_kv_read(kv, "app/db", &json), "kv_read")) {
        printf("JSON bruto: %s\n", json);   /* parseie com cJSON/jsmn se precisar */
        vault_free_secret(json);
        json = NULL;
    }

    if (check(vault_kv_list(kv, "app", &keys), "kv_list")) {
        n = vault_strlist_count(keys);
        for (i = 0; i < n; ++i)
            printf("chave[%u] = %s\n", (unsigned)i, vault_strlist_get(keys, i));
        vault_strlist_free(keys);
        keys = NULL;
    }

    /* --- Transit (requer: vault secrets enable transit) --- */
    if (check(vault_transit_create_key(client, "minha-chave", NULL), "transit_create_key") &&
        check(vault_transit_encrypt(client, "minha-chave", msg, strlen(msg), &ct), "transit_encrypt")) {
        printf("ciphertext = %s\n", ct);
        if (check(vault_transit_decrypt(client, "minha-chave", ct, &plain, &plain_len), "transit_decrypt"))
            printf("plaintext  = %s (%u bytes)\n", (const char *)plain, (unsigned)plain_len);
        vault_free_secret((char *)plain);
        plain = NULL;
        vault_free(ct);
        ct = NULL;
    }

    /* --- Sys/mounts --- */
    if (check(vault_sys_mounts_list(client, &json), "mounts_list")) {
        printf("mounts: %s\n", json);
        vault_free(json);
        json = NULL;
    }

    rc = 0;

done:
    /* ordem: kv antes do client */
    vault_kv_free(kv);
    vault_client_free(client);
    return rc;
}
