/*
 * vaultc.cpp - Shim extern "C" sobre a libvault (C++17).
 * Compilar com toolchain moderna, junto com libvault, libcurl e nlohmann/json.
 *
 * NOTA SOBRE A API DA LIBVAULT
 * As linhas marcadas com [API] dependem de assinaturas da libvault que podem
 * variar entre versoes (escrito com base no README da 0.63.0). Se o compilador
 * reclamar, o ajuste e' sempre local a essas linhas; o cabecalho C nao muda.
 */
#define VAULTC_BUILD_DLL
#include "vaultc.h"

#include <libvault/VaultClient.h>   /* [API] cabecalho principal */
#include <nlohmann/json.hpp>

#include <cstdlib>
#include <cstring>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <vector>

using json = nlohmann::json;

/* ------------------------------------------------------------------ */
/* Erro por thread                                                     */
/* ------------------------------------------------------------------ */
static thread_local std::string g_err;

static void set_err(const std::string &s) { g_err = s; }

static vault_status_t fail(vault_status_t st, const char *msg)
{
    set_err(msg);
    return st;
}

static vault_status_t request_failed()
{
    if (g_err.empty()) set_err("request failed or empty response");
    return VAULT_ERR_REQUEST;
}

template <class F>
static vault_status_t guarded(F &&f)
{
    g_err.clear();
    try {
        return f();
    } catch (const std::bad_alloc &) {
        return fail(VAULT_ERR_NOMEM, "out of memory");
    } catch (const std::exception &e) {
        return fail(VAULT_ERR_EXCEPTION, e.what());
    } catch (...) {
        return fail(VAULT_ERR_EXCEPTION, "unknown C++ exception");
    }
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */
static char *dup_bytes(const void *p, size_t n)
{
    char *r = static_cast<char *>(std::malloc(n + 1));
    if (!r) return nullptr;
    if (n) std::memcpy(r, p, n);
    r[n] = '\0';
    return r;
}

static vault_status_t emit_string(const std::string &s, char **out)
{
    char *p = dup_bytes(s.data(), s.size());
    if (!p) return fail(VAULT_ERR_NOMEM, "out of memory");
    *out = p;
    return VAULT_OK;
}

/* create/update/delete podem devolver bool ou optional<...> conforme a versao */
static bool ok(bool b) { return b; }
template <class T>
static bool ok(const std::optional<T> &o) { return o.has_value(); }

static bool to_list(const std::optional<std::vector<std::string>> &r,
                    std::vector<std::string> &out)
{
    if (!r) return false;
    out = *r;
    return true;
}

/* variante caso list() devolva o JSON bruto: {"data":{"keys":[...]}} */
static bool to_list(const std::optional<std::string> &r,
                    std::vector<std::string> &out)
{
    if (!r) return false;
    json j = json::parse(*r, nullptr, false);
    if (j.is_discarded()) return false;
    auto d = j.find("data");
    if (d == j.end() || !d->is_object()) return false;
    auto k = d->find("keys");
    if (k == d->end() || !k->is_array()) return false;
    for (const auto &e : *k)
        if (e.is_string()) out.push_back(e.get<std::string>());
    return true;
}

static bool build_params(const vault_kv_pair_t *pairs, size_t count,
                         Vault::Parameters &out)           /* [API] */
{
    if (count && !pairs) return false;
    for (size_t i = 0; i < count; ++i) {
        if (!pairs[i].key || !pairs[i].value) return false;
        out[pairs[i].key] = pairs[i].value;
    }
    return true;
}

/* ---- base64 (Transit exige plaintext em base64) ---- */
static std::string b64_encode(const unsigned char *d, size_t n)
{
    static const char T[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string o;
    o.reserve(((n + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 2 < n; i += 3) {
        unsigned v = (d[i] << 16) | (d[i + 1] << 8) | d[i + 2];
        o += T[(v >> 18) & 63]; o += T[(v >> 12) & 63];
        o += T[(v >> 6) & 63];  o += T[v & 63];
    }
    if (i + 1 == n) {
        unsigned v = d[i] << 16;
        o += T[(v >> 18) & 63]; o += T[(v >> 12) & 63]; o += "==";
    } else if (i + 2 == n) {
        unsigned v = (d[i] << 16) | (d[i + 1] << 8);
        o += T[(v >> 18) & 63]; o += T[(v >> 12) & 63];
        o += T[(v >> 6) & 63];  o += '=';
    }
    return o;
}

static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static bool b64_decode(const std::string &in, std::string &out)
{
    unsigned val = 0;
    int bits = -8;
    for (char c : in) {
        if (c == '=') break;
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        int v = b64_val(c);
        if (v < 0) return false;
        val = (val << 6) | static_cast<unsigned>(v);
        bits += 6;
        if (bits >= 0) {
            out.push_back(static_cast<char>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* Tipos opacos                                                        */
/* ------------------------------------------------------------------ */
struct vault_client_s {
    /* A estrategia fica no mesmo objeto e e' declarada ANTES do Client, para
     * sobreviver a ele caso a libvault guarde uma referencia a ela. */
    std::shared_ptr<void>         strategy;
    std::unique_ptr<Vault::Client> client;
};

struct vault_kv_s {
    Vault::KeyValue kv;                                    /* [API] */
    bool            v2;
    vault_kv_s(Vault::Client &c, const char *mount, vault_kv_version_t ver)
        : kv(c, Vault::SecretMount{mount},                 /* [API] */
             ver == VAULT_KV_V2 ? Vault::KeyValue::Version::v2
                                : Vault::KeyValue::Version::v1),
          v2(ver == VAULT_KV_V2) {}
};

struct vault_strlist_s {
    std::vector<std::string> items;
};

/* ------------------------------------------------------------------ */
/* Utilitarios gerais                                                  */
/* ------------------------------------------------------------------ */
extern "C" {

VAULTC_API int VAULTC_CALL vault_abi_version(void) { return VAULT_ABI_VERSION; }

VAULTC_API const char *VAULTC_CALL vault_version(void) { return "vaultc 1.0.0"; }

VAULTC_API const char *VAULTC_CALL vault_status_string(vault_status_t s)
{
    switch (s) {
    case VAULT_OK:              return "ok";
    case VAULT_ERR_INVALID_ARG: return "invalid argument";
    case VAULT_ERR_NOMEM:       return "out of memory";
    case VAULT_ERR_AUTH:        return "authentication failed";
    case VAULT_ERR_REQUEST:     return "request failed";
    case VAULT_ERR_NOT_FOUND:   return "not found";
    case VAULT_ERR_PARSE:       return "unexpected response format";
    case VAULT_ERR_EXCEPTION:   return "internal exception";
    }
    return "unknown status";
}

VAULTC_API const char *VAULTC_CALL vault_last_error(void) { return g_err.c_str(); }

VAULTC_API void VAULTC_CALL vault_free(void *p) { std::free(p); }

VAULTC_API void VAULTC_CALL vault_free_secret(char *s)
{
    if (!s) return;
    volatile char *v = s;                  /* evita eliminacao pelo otimizador */
    for (size_t n = std::strlen(s); n > 0; --n) *v++ = 0;
    std::free(s);
}

/* ------------------------------------------------------------------ */
/* Configuracao e cliente                                              */
/* ------------------------------------------------------------------ */
VAULTC_API void VAULTC_CALL vault_config_init(vault_config_t *c)
{
    if (!c) return;
    std::memset(c, 0, sizeof(*c));
    c->struct_size = sizeof(*c);
    c->host        = "localhost";
    c->port        = 8200;
    c->tls_enabled = 1;
    c->tls_verify  = 1;
    c->debug       = 0;
}

} /* extern "C" */

static Vault::Config build_config(const vault_config_t *c)
{
    return Vault::ConfigBuilder()                                   /* [API] */
        .withHost(Vault::Host{c->host ? c->host : "localhost"})     /* [API] */
        .withPort(Vault::Port{std::to_string(c->port)})             /* [API] Port pode ser string */
        .withTlsEnabled(c->tls_enabled != 0)                        /* [API] */
        .withTlsVerification(c->tls_verify != 0)                    /* [API] */
        .withDebug(c->debug != 0)                                   /* [API] */
        .build();
}

template <class Strategy>
static vault_status_t build_client(const vault_config_t *cfg,
                                   std::shared_ptr<Strategy> strat,
                                   vault_client_t **out)
{
    Vault::HttpErrorCallback cb = [](std::string e) { set_err(e); };  /* [API] */

    std::unique_ptr<vault_client_s> h(new vault_client_s());
    h->strategy = strat;
    h->client.reset(new Vault::Client(build_config(cfg), *strat, cb)); /* [API] */

    if (!h->client->is_authenticated()) {                              /* [API] */
        if (g_err.empty()) set_err("authentication failed");
        return VAULT_ERR_AUTH;
    }
    *out = h.release();
    return VAULT_OK;
}

static bool config_valid(const vault_config_t *c)
{
    return c && c->struct_size >= sizeof(vault_config_t);
}

extern "C" {

VAULTC_API vault_status_t VAULTC_CALL
vault_client_new_token(const vault_config_t *cfg, const char *token,
                       vault_client_t **out)
{
    return guarded([&]() -> vault_status_t {
        if (out) *out = nullptr;
        if (!out || !token || !config_valid(cfg))
            return fail(VAULT_ERR_INVALID_ARG, "invalid argument");
        auto s = std::make_shared<Vault::TokenStrategy>(Vault::Token{token}); /* [API] */
        return build_client(cfg, s, out);
    });
}

VAULTC_API vault_status_t VAULTC_CALL
vault_client_new_approle(const vault_config_t *cfg, const char *role_id,
                         const char *secret_id, vault_client_t **out)
{
    return guarded([&]() -> vault_status_t {
        if (out) *out = nullptr;
        if (!out || !role_id || !secret_id || !config_valid(cfg))
            return fail(VAULT_ERR_INVALID_ARG, "invalid argument");
        auto s = std::make_shared<Vault::AppRoleStrategy>(                    /* [API] */
            Vault::RoleId{role_id}, Vault::SecretId{secret_id});
        return build_client(cfg, s, out);
    });
}

VAULTC_API void VAULTC_CALL vault_client_free(vault_client_t *c)
{
    delete c;   /* destroi Client antes da strategy (ordem inversa de declaracao) */
}

VAULTC_API int VAULTC_CALL vault_client_is_authenticated(const vault_client_t *c)
{
    try {
        return (c && c->client && c->client->is_authenticated()) ? 1 : 0;  /* [API] */
    } catch (...) {
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/* Lista de strings                                                    */
/* ------------------------------------------------------------------ */
VAULTC_API size_t VAULTC_CALL vault_strlist_count(const vault_strlist_t *l)
{
    return l ? l->items.size() : 0;
}

VAULTC_API const char *VAULTC_CALL
vault_strlist_get(const vault_strlist_t *l, size_t i)
{
    return (l && i < l->items.size()) ? l->items[i].c_str() : nullptr;
}

VAULTC_API void VAULTC_CALL vault_strlist_free(vault_strlist_t *l) { delete l; }

/* ------------------------------------------------------------------ */
/* Key/Value                                                           */
/* ------------------------------------------------------------------ */
VAULTC_API vault_status_t VAULTC_CALL
vault_kv_new(vault_client_t *c, const char *mount, vault_kv_version_t ver,
             vault_kv_t **out)
{
    return guarded([&]() -> vault_status_t {
        if (out) *out = nullptr;
        if (!c || !c->client || !mount || !out ||
            (ver != VAULT_KV_V1 && ver != VAULT_KV_V2))
            return fail(VAULT_ERR_INVALID_ARG, "invalid argument");
        *out = new vault_kv_s(*c->client, mount, ver);
        return VAULT_OK;
    });
}

VAULTC_API void VAULTC_CALL vault_kv_free(vault_kv_t *kv) { delete kv; }

VAULTC_API vault_status_t VAULTC_CALL
vault_kv_read(vault_kv_t *kv, const char *path, char **out_json)
{
    return guarded([&]() -> vault_status_t {
        if (out_json) *out_json = nullptr;
        if (!kv || !path || !out_json)
            return fail(VAULT_ERR_INVALID_ARG, "invalid argument");
        auto r = kv->kv.read(Vault::Path{path});                    /* [API] */
        if (!r) return request_failed();
        return emit_string(*r, out_json);
    });
}

VAULTC_API vault_status_t VAULTC_CALL
vault_kv_read_value(vault_kv_t *kv, const char *path, const char *field,
                    char **out_value)
{
    return guarded([&]() -> vault_status_t {
        if (out_value) *out_value = nullptr;
        if (!kv || !path || !field || !out_value)
            return fail(VAULT_ERR_INVALID_ARG, "invalid argument");
        auto r = kv->kv.read(Vault::Path{path});                    /* [API] */
        if (!r) return request_failed();

        json j = json::parse(*r, nullptr, false);
        if (j.is_discarded()) return fail(VAULT_ERR_PARSE, "response is not valid JSON");

        const json *d = &j;
        auto it = j.find("data");
        if (it == j.end() || !it->is_object())
            return fail(VAULT_ERR_PARSE, "response has no 'data' object");
        d = &*it;
        if (kv->v2) {                      /* KV v2: data.data.<campo> */
            auto it2 = d->find("data");
            if (it2 != d->end() && it2->is_object()) d = &*it2;
        }
        auto f = d->find(field);
        if (f == d->end()) return fail(VAULT_ERR_NOT_FOUND, "field not found");

        return emit_string(f->is_string() ? f->get<std::string>() : f->dump(),
                           out_value);
    });
}

VAULTC_API vault_status_t VAULTC_CALL
vault_kv_create(vault_kv_t *kv, const char *path,
                const vault_kv_pair_t *pairs, size_t count)
{
    return guarded([&]() -> vault_status_t {
        Vault::Parameters p;                                         /* [API] */
        if (!kv || !path || !build_params(pairs, count, p))
            return fail(VAULT_ERR_INVALID_ARG, "invalid argument");
        auto r = kv->kv.create(Vault::Path{path}, p);               /* [API] */
        return ok(r) ? VAULT_OK : request_failed();
    });
}

VAULTC_API vault_status_t VAULTC_CALL
vault_kv_update(vault_kv_t *kv, const char *path,
                const vault_kv_pair_t *pairs, size_t count)
{
    return guarded([&]() -> vault_status_t {
        Vault::Parameters p;                                         /* [API] */
        if (!kv || !path || !build_params(pairs, count, p))
            return fail(VAULT_ERR_INVALID_ARG, "invalid argument");
        auto r = kv->kv.update(Vault::Path{path}, p);               /* [API] */
        return ok(r) ? VAULT_OK : request_failed();
    });
}

VAULTC_API vault_status_t VAULTC_CALL
vault_kv_delete(vault_kv_t *kv, const char *path)
{
    return guarded([&]() -> vault_status_t {
        if (!kv || !path) return fail(VAULT_ERR_INVALID_ARG, "invalid argument");
        auto r = kv->kv.del(Vault::Path{path});                     /* [API] */
        return ok(r) ? VAULT_OK : request_failed();
    });
}

VAULTC_API vault_status_t VAULTC_CALL
vault_kv_list(vault_kv_t *kv, const char *path, vault_strlist_t **out)
{
    return guarded([&]() -> vault_status_t {
        if (out) *out = nullptr;
        if (!kv || !path || !out)
            return fail(VAULT_ERR_INVALID_ARG, "invalid argument");
        auto r = kv->kv.list(Vault::Path{path});                    /* [API] */
        std::unique_ptr<vault_strlist_s> l(new vault_strlist_s());
        if (!to_list(r, l->items)) return request_failed();
        *out = l.release();
        return VAULT_OK;
    });
}

/* ------------------------------------------------------------------ */
/* Transit                                                             */
/* ------------------------------------------------------------------ */
VAULTC_API vault_status_t VAULTC_CALL
vault_transit_create_key(vault_client_t *c, const char *name, const char *type)
{
    return guarded([&]() -> vault_status_t {
        if (!c || !c->client || !name)
            return fail(VAULT_ERR_INVALID_ARG, "invalid argument");
        Vault::Transit tr{*c->client};                              /* [API] */
        Vault::Parameters p;
        if (type) p["type"] = type;
        auto r = tr.createKey(Vault::Path{name}, p);                /* [API] */
        return ok(r) ? VAULT_OK : request_failed();
    });
}

VAULTC_API vault_status_t VAULTC_CALL
vault_transit_rotate_key(vault_client_t *c, const char *name)
{
    return guarded([&]() -> vault_status_t {
        if (!c || !c->client || !name)
            return fail(VAULT_ERR_INVALID_ARG, "invalid argument");
        Vault::Transit tr{*c->client};                              /* [API] */
        auto r = tr.rotateKey(Vault::Path{name});                   /* [API] */
        return ok(r) ? VAULT_OK : request_failed();
    });
}

VAULTC_API vault_status_t VAULTC_CALL
vault_transit_encrypt(vault_client_t *c, const char *name,
                      const void *data, size_t len, char **out_ct)
{
    return guarded([&]() -> vault_status_t {
        if (out_ct) *out_ct = nullptr;
        if (!c || !c->client || !name || !out_ct || (len && !data))
            return fail(VAULT_ERR_INVALID_ARG, "invalid argument");
        Vault::Transit tr{*c->client};                              /* [API] */
        Vault::Parameters p;
        p["plaintext"] = b64_encode(static_cast<const unsigned char *>(data), len);
        auto r = tr.encrypt(Vault::Path{name}, p);                  /* [API] */
        if (!r) return request_failed();

        json j = json::parse(*r, nullptr, false);
        if (j.is_discarded()) return fail(VAULT_ERR_PARSE, "response is not valid JSON");
        auto d = j.find("data");
        if (d == j.end() || !d->is_object()) return fail(VAULT_ERR_PARSE, "no 'data' in response");
        auto ct = d->find("ciphertext");
        if (ct == d->end() || !ct->is_string()) return fail(VAULT_ERR_NOT_FOUND, "no 'ciphertext' in response");
        return emit_string(ct->get<std::string>(), out_ct);
    });
}

VAULTC_API vault_status_t VAULTC_CALL
vault_transit_decrypt(vault_client_t *c, const char *name, const char *ciphertext,
                      unsigned char **out_data, size_t *out_len)
{
    return guarded([&]() -> vault_status_t {
        if (out_data) *out_data = nullptr;
        if (out_len) *out_len = 0;
        if (!c || !c->client || !name || !ciphertext || !out_data || !out_len)
            return fail(VAULT_ERR_INVALID_ARG, "invalid argument");
        Vault::Transit tr{*c->client};                              /* [API] */
        Vault::Parameters p;
        p["ciphertext"] = ciphertext;
        auto r = tr.decrypt(Vault::Path{name}, p);                  /* [API] */
        if (!r) return request_failed();

        json j = json::parse(*r, nullptr, false);
        if (j.is_discarded()) return fail(VAULT_ERR_PARSE, "response is not valid JSON");
        auto d = j.find("data");
        if (d == j.end() || !d->is_object()) return fail(VAULT_ERR_PARSE, "no 'data' in response");
        auto pt = d->find("plaintext");
        if (pt == d->end() || !pt->is_string()) return fail(VAULT_ERR_NOT_FOUND, "no 'plaintext' in response");

        std::string raw;
        if (!b64_decode(pt->get<std::string>(), raw))
            return fail(VAULT_ERR_PARSE, "plaintext is not valid base64");
        char *buf = dup_bytes(raw.data(), raw.size());
        if (!buf) return fail(VAULT_ERR_NOMEM, "out of memory");
        *out_data = reinterpret_cast<unsigned char *>(buf);
        *out_len  = raw.size();
        return VAULT_OK;
    });
}

/* ------------------------------------------------------------------ */
/* Sys / mounts                                                        */
/* ------------------------------------------------------------------ */
VAULTC_API vault_status_t VAULTC_CALL
vault_sys_mounts_list(vault_client_t *c, char **out_json)
{
    return guarded([&]() -> vault_status_t {
        if (out_json) *out_json = nullptr;
        if (!c || !c->client || !out_json)
            return fail(VAULT_ERR_INVALID_ARG, "invalid argument");
        Vault::Sys::Mounts m{*c->client};                           /* [API] */
        auto r = m.list();                                          /* [API] */
        if (!r) return request_failed();
        return emit_string(*r, out_json);
    });
}

VAULTC_API vault_status_t VAULTC_CALL
vault_sys_mounts_enable(vault_client_t *c, const char *path, const char *type,
                        const vault_kv_pair_t *opts, size_t count)
{
    return guarded([&]() -> vault_status_t {
        Vault::Parameters p;                                         /* [API] */
        if (!c || !c->client || !path || !type || !build_params(opts, count, p))
            return fail(VAULT_ERR_INVALID_ARG, "invalid argument");
        p["type"] = type;
        Vault::Sys::Mounts m{*c->client};                           /* [API] */
        auto r = m.enable(Vault::Path{path}, p);                    /* [API] */
        return ok(r) ? VAULT_OK : request_failed();
    });
}

VAULTC_API vault_status_t VAULTC_CALL
vault_sys_mounts_disable(vault_client_t *c, const char *path)
{
    return guarded([&]() -> vault_status_t {
        if (!c || !c->client || !path)
            return fail(VAULT_ERR_INVALID_ARG, "invalid argument");
        Vault::Sys::Mounts m{*c->client};                           /* [API] */
        auto r = m.disable(Vault::Path{path});                      /* [API] */
        return ok(r) ? VAULT_OK : request_failed();
    });
}

} /* extern "C" */
