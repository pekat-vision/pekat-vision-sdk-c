/* PEKAT VISION api                                                    */
/*                                                                     */
/* A .NET module for communication with PEKAT VISION 3.10.2 and higher */
/*                                                                     */
/* Author: developers@pekatvision.com                                  */
/* Date:   7 May 2020                                                  */
/* Web:    https://github.com/pekat-vision                             */

#include "sdk.h"
#include <Windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* enable socket lib */
#pragma comment(lib,"Ws2_32.lib")

#define SERVER_PATH "\\pekat_vision\\pekat_vision.exe"

/* in tenths of second (10 == 1 sec) but it looks like each connect attempt takes at least 2 seconds */
#define START_WAIT_TIME 8

#define FROM_PORT 10000
#define TO_PORT 30000

#define USER_AGENT L"PekatVisionSDK"
#define CONTEXT_HEADER L"ContextBase64utf"
#define IMAGE_LEN_HEADER L"ImageLen"

int get_image_len(HINTERNET hRequest);

/* Get length of string in wide chars including terminating zero (how many needed to allocate for conversion). -1 on error */
static int get_wide_len(const char *s) {
    size_t len;
    return mbstowcs_s(&len, NULL, 0, s, 0) ? -1 : (int)len;
}

/* Append "narrow" string to wide string. Passed len is size of target buffer. Returns non-zero on error. */
static int append_narrow(wchar_t* t, size_t len, const char* s) {
    size_t l = wcslen(t);
    return mbstowcs_s(NULL, t + l, len - l, s, len - l - 1);
}

/* Append wide string to wide string. Passed len is size of target buffer. Returns non-zero on error. */
static int append_wide(wchar_t* t, size_t len, const wchar_t* s) {
    size_t l = wcslen(t);
    return wcscat_s(t + l, len - l, s);
}

static int url_encode_char(char c) {
    /* encode everything except totally safe characters */
    return !(('0' <= c && c <= '9') || ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z'));
}

static const wchar_t *HEX = L"0123456789ABCDEF";

/* Get number of character when string is URL encoded */
static size_t get_url_encoded_len(const char *input) {
    size_t len = 0;
    while (*input) {
        if (url_encode_char(*input++))
            len += 3;
        else
            len++;
    }
    return len;
}

/* URL encode string into buffer. It must be large enough to hold the string and terminating zero. */
static void url_encode(wchar_t *dst, const char *src) {
    while (*src) {
        char c = *src++;
        if (url_encode_char(c)) {
            *dst++ = L'%';
            *dst++ = HEX[(c >> 4) & 0xf];
            *dst++ = HEX[c & 0xf];
        } else {
            /* must be ASCII */
            *dst++ = (wchar_t)c;
        }
    }
    *dst = 0;
}

struct _pv_analyzer {
    HINTERNET hSession;
    HINTERNET hConnect;

    wchar_t* host;
    int port;
    /* running process or 0 if none */
    HANDLE hProcess;
    int stop_key;
    wchar_t* api_key;
    unsigned char context_in_body;
    /* following are filled in by response data */
    char* response_data;
    unsigned int response_size;
    unsigned int response_limit;
    char* response_context;
};

void pv_set_context_in_body(pv_analyzer *analyzer, unsigned char context_in_body) {
    analyzer->context_in_body = context_in_body;
}

void pv_free_analyzer(pv_analyzer* analyzer) {
    if (analyzer->hProcess) {
        /* stop process */
        wchar_t path[50];
        swprintf_s(path, sizeof(path) / sizeof(wchar_t), L"/stop?key=%d", analyzer->stop_key);
        HINTERNET hRequest = WinHttpOpenRequest(analyzer->hConnect, L"GET", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (hRequest) {
            WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        } else {
            /* failed to send - kill instead */
            TerminateProcess(analyzer->hProcess, 0);
        }
        WinHttpCloseHandle(hRequest);
        WaitForSingleObject(analyzer->hProcess, INFINITE);
        CloseHandle(analyzer->hProcess);
    }
    if (analyzer->host)
        free(analyzer->host);
    if (analyzer->hConnect)
        WinHttpCloseHandle(analyzer->hConnect);
    if (analyzer->hSession)
        WinHttpCloseHandle(analyzer->hSession);
    if (analyzer->api_key)
        free(analyzer->api_key);
    if (analyzer->response_data)
        free(analyzer->response_data);
    if (analyzer->response_context)
        free(analyzer->response_context);
    free(analyzer);
}

static pv_analyzer* alloc_analyzer(const char *host, int port, const char* api_key) {
    pv_analyzer* analyzer = malloc(sizeof(pv_analyzer));
    if (!analyzer)
        return NULL;
    analyzer->host = NULL;
    analyzer->port = port;
    analyzer->hSession = 0;
    analyzer->hConnect = 0;
    analyzer->hProcess = 0;
    analyzer->api_key = NULL;
    analyzer->response_data = NULL;
    analyzer->response_size = 0;
    analyzer->response_limit = 0;
    analyzer->response_context = NULL;
    analyzer->context_in_body = 1;

    if (host) {
        int len = get_wide_len(host);
        if (len < 0)
            goto error;
        analyzer->host = malloc(len * sizeof(wchar_t));
        if (!analyzer->host)
            goto error;
        *analyzer->host = 0;
        if (append_narrow(analyzer->host, len, host))
            goto error;
    }

    if (api_key) {
        size_t len = get_url_encoded_len(api_key) + 1;
        analyzer->api_key = malloc(len * sizeof(wchar_t));
        if (!analyzer->api_key)
            goto error;
        url_encode(analyzer->api_key, api_key);
    }

    return analyzer;

error:
    pv_free_analyzer(analyzer);
    return NULL;
}

static int wait_server_start(pv_analyzer* analyzer) {
    HINTERNET hSession = 0;
    HINTERNET hConnect = 0;
    HINTERNET hRequest  = 0;

    hSession = WinHttpOpen(USER_AGENT, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession)
        goto error;
    hConnect = WinHttpConnect(hSession, analyzer->host, analyzer->port, 0);
    if (!hConnect)
        goto error;
    hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/ping", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest)
        goto error;

    /* wait for server start */
    for (int i = 0; i < START_WAIT_TIME; i++) {
        /* ping server */
        if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
            if (WinHttpReceiveResponse(hRequest, NULL)) {
                DWORD status = 0;
                DWORD size = sizeof(status);

                /* check status code */
                BOOL res = WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX);
                if (res && status == 200) {
                    /* put session and connect to analyzer */
                    analyzer->hSession = hSession;
                    analyzer->hConnect = hConnect;
                    /* clear request */
                    WinHttpCloseHandle(hRequest);
                    return 0;
                }
                /* any other status means failed */
                goto error;
            }
        }

        /* not running process or process died - exit */
        if (!analyzer->hProcess || WaitForSingleObject(analyzer->hProcess, 0) != WAIT_TIMEOUT) {
            return -1;
        }

        /* sleep */
        Sleep(100);
    }

error:
    if (hRequest)
        WinHttpCloseHandle(hRequest);
    if (hConnect)
        WinHttpCloseHandle(hConnect);
    if (hSession)
        WinHttpCloseHandle(hSession);
    return -1;
}

/* find two free consecutive ports */
static int find_port() {
    struct sockaddr_in addr;
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData))
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;

    int last_port = 0;
    for (int p = FROM_PORT; p < TO_PORT; p++) {
        addr.sin_port = htons(p);
        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0)
            return -1;
        int res = bind(s, (struct sockaddr*) & addr, sizeof(addr));
        closesocket(s);
        if (res)
            /* failed - clear last */
            last_port = 0;
        else if (last_port)
            /* last set - found */
            return last_port;
        else
            /* last empty - set */
            last_port = p;
    }
    /* not found */
    return -1;
}

pv_analyzer* pv_create_local_analyzer(const char* dist_path, const char* project_path, const char* api_key, char* const argv[]) {
    /* detect port */
    int port = find_port();
    if (port == -1)
        return NULL;

    /* calculate cmdline length */
    size_t len = strlen(dist_path) + strlen(SERVER_PATH) + strlen(project_path) + (api_key ? strlen(api_key) : 0) + 100; /* 100 is for parameter names and separators */
    if (argv) {
        for (char* const* a = argv; *a; len += strlen(*a++) + 3); /* 3 for space and quotes */
    }
    /* construct cmdline */
    char *cmdline = malloc(len);
    if (!cmdline)
        return NULL;
    /* generate stop key */
    srand((unsigned int)time(NULL));
    int stop_key = rand();
    snprintf(cmdline, len, "\"%s%s\" -data \"%s\" -host 127.0.0.1 -port %d -stop_key %d", dist_path, SERVER_PATH, project_path, port, stop_key);
    size_t pos = strlen(cmdline);
    len -= pos;
    if (api_key) {
        snprintf(cmdline + pos, len, " -api_key \"%s\"", api_key);
        pos = strlen(cmdline);
        len -= pos;
    }
    if (argv) {
        for (char* const* a = argv; *a;) {
            snprintf(cmdline + pos, len, " \"%s\"", *a++);
            pos = strlen(cmdline);
            len -= pos;
        }
    }

    /* allocate analyzer before exec so we don't have to kill process when alloc fails */
    pv_analyzer *analyzer = alloc_analyzer("127.0.0.1", port, api_key);
    if (!analyzer) {
        free(cmdline);
        return NULL;
    }

    /* start process */
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    BOOL res = CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    free(cmdline);
    if (!res) {
        /* exec failed */
        pv_free_analyzer(analyzer);
        return NULL;
    }

    /* put process to analyzer */
    analyzer->hProcess = pi.hProcess;
    analyzer->stop_key = stop_key;
    /* thread not needed */
    CloseHandle(pi.hThread);
    /* wait for start */
    if (wait_server_start(analyzer)) {
        pv_free_analyzer(analyzer);
        return NULL;
    }
    return analyzer;
}

pv_analyzer* pv_create_remote_analyzer(const char* host, int port, const char* api_key) {
    if (!host || !*host || port <= 0 || port >= 65536)
        return NULL;

    pv_analyzer* analyzer = alloc_analyzer(host, port, api_key);
    if (!analyzer)
        return NULL;
    if (wait_server_start(analyzer)) {
        pv_free_analyzer(analyzer);
        return NULL;
    }
    return analyzer;
}

pv_analyzer* pv_clone_analyzer(pv_analyzer* orig) {
    pv_analyzer* analyzer = alloc_analyzer(NULL, orig->port, NULL);
    if (!analyzer)
        return NULL;
    /* set host by copying */
    analyzer->host = _wcsdup(orig->host);
    if (!analyzer->host)
        goto error;
    /* set api key by copying */
    if (orig->api_key) {
        analyzer->api_key = _wcsdup(orig->api_key);
        if (!analyzer->api_key)
            goto error;
    }
    /* create winhttp handles */
    analyzer->hSession = WinHttpOpen(USER_AGENT, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!analyzer->hSession)
        goto error;
    analyzer->hConnect = WinHttpConnect(analyzer->hSession, analyzer->host, analyzer->port, 0);
    if (!analyzer->hConnect)
        goto error;

    return analyzer;

error:
    pv_free_analyzer(analyzer);
    return NULL;
}

static int base64_table[] = {
    /* + */ 62,
    -1, -1, -1,
    /* / */ 63,
    /* 0-9 */ 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
    -1, -1, -1, -1, -1, -1, -1,
    /* A-Z */ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    -1, -1, -1, -1, -1, -1,
    /* a-z */ 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
};

static char* base64_decode(wchar_t* buffer) {
    size_t len, tlen;
    int accu;
    char* tbuffer;

    len = wcslen(buffer);
    /* too short */
    if (len < 4)
        return NULL;

    /* get decoded size */
    tlen = len / 4 * 3;
    if (buffer[len - 2] == '=')
        tlen--;
    if (buffer[len - 1] == '=')
        tlen--;
    /* terminating zero */
    tlen++;

    /* allocate */
    tbuffer = malloc(tlen);
    if (!tbuffer)
        return NULL;

    /* decode */
    for (size_t i = 0, j = 0; j < tlen - 1; i++) {
        int b;
        wchar_t c = buffer[i];

        /* check and decode */
        if (c < 0x2b || c > 0x7a || (b = base64_table[c - 0x2b]) < 0) {
            /* wrong character */
            free(tbuffer);
            return NULL;
        }
        switch (i & 3) {
        case 0: accu = b << 2; break;
        case 1: tbuffer[j++] = accu | b >> 4; accu = b << 4; break;
        case 2: tbuffer[j++] = accu | b >> 2; accu = b << 6; break;
        case 3: tbuffer[j++] = accu | b; break;
        }
    }
    /* terminating zero */
    tbuffer[tlen - 1] = 0;
    return tbuffer;
}

/* must be in sync with response_type enum */
static wchar_t* response_types[] = { L"context", L"annotated_image", L"heatmap" };



int pv_analyze_image_impl(pv_analyzer* analyzer, const char* image, int len, pv_result_type result_type, const char* data, const wchar_t* _path, const wchar_t* dim) {
    HINTERNET hRequest = 0;
    wchar_t* path = NULL;
    int error = 0;

    /* cleanup first */
    analyzer->response_size = 0;
    if (analyzer->response_context) {
        free(analyzer->response_context);
        analyzer->response_context = NULL;
    }
    /* get path and query length */
    /* base size for path, response type and other potential param names */
    size_t l = 70;
    /* path */
    l += wcslen(_path);
    /* api_key */
    l += analyzer->api_key ? wcslen(analyzer->api_key) : 0;
    /* dimensions */
    if (dim) {
        l += wcslen(dim);
    }
    /* data */
    if (data) {
        l += get_url_encoded_len(data);
    }
    /* construct path with query */
    path = malloc(l * sizeof(wchar_t));
    if (!path)
        return PVR_NOMEM;
    *path = 0;
    int append_res = append_wide(path, l, _path);
    append_res |= append_wide(path, l, L"?response_type=");
    append_res |= append_wide(path, l, response_types[result_type]);
    if (analyzer->api_key) {
        append_res |= append_wide(path, l, L"&api_key=");
        append_res |= append_wide(path, l, analyzer->api_key);
    }
    if (dim) {
        append_res |= append_wide(path, l, dim);
    }
    if (analyzer->context_in_body != 0) {
        append_res |= append_wide(path, l, L"&context_in_body");
    }
    if (data) {
        append_res |= append_wide(path, l, L"&data=");
        url_encode(path + wcslen(path), data);
    }
    if (append_res) {
        free(path);
        return PVR_WRONG_MBS;
    }

    /* prepare error code so we can just jumpt to error */
    error = PVR_WINHTTP;
    /* send request */
    hRequest = WinHttpOpenRequest(analyzer->hConnect, L"POST", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest)
        goto error;
    if (!WinHttpSendRequest(hRequest, L"Content-Type: application/octet-stream", -1, (LPVOID)image, len, len, 0))
        goto error;
    if (!WinHttpReceiveResponse(hRequest, NULL))
        goto error;

    /* check status code */
    DWORD status = 0;
    DWORD size = sizeof(status);
    if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX))
        goto error;
    if (status != 200) {
        /* wrong status */
        error = status;
        goto error;
    }

    if (!analyzer->context_in_body) {
        /* get context from header */
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CUSTOM, CONTEXT_HEADER, WINHTTP_NO_OUTPUT_BUFFER, &size, WINHTTP_NO_HEADER_INDEX);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            wchar_t *context = malloc(size);
            if (!context) {
                error = PVR_NOMEM;
                goto error;
            }
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CUSTOM, CONTEXT_HEADER, context, &size, WINHTTP_NO_HEADER_INDEX)) {
                analyzer->response_context = base64_decode(context);
            }
            free(context);
        }
        
        /* otherwise ignore error and continue without context */

        /* preallocate data buffer according to content length */
        DWORD contentLen;
        size = sizeof(contentLen);
        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &contentLen, &size, WINHTTP_NO_HEADER_INDEX)) {
        /* content length read, adjust buffer as needed */
            if (analyzer->response_limit < contentLen) {
                if (analyzer->response_data)
                    free(analyzer->response_data);
                analyzer->response_size = 0;
                analyzer->response_data = malloc(contentLen);
                if (!analyzer->response_data) {
                    analyzer->response_limit = 0;
                    error = PVR_NOMEM;
                    goto error;
                }
                analyzer->response_limit = contentLen;
            }
        }

        /* read data */
        DWORD pos = 0;
        DWORD read;
        do {
            if (!WinHttpQueryDataAvailable(hRequest, &size))
                goto error;

            DWORD new_pos = pos + size;
            if (new_pos > analyzer->response_limit) {
                /* resize needed */
                char* new_data = realloc(analyzer->response_data, new_pos);
                if (!new_data) {
                    error = PVR_NOMEM;
                    goto error;
                }
                analyzer->response_data = new_data;
                analyzer->response_limit = new_pos;
            }
            if (!WinHttpReadData(hRequest, (LPVOID)(analyzer->response_data + pos), size, &read)) {
                goto error;
            }
            pos += read;
        } while (read > 0);
        analyzer->response_size = pos;

        if (result_type == PVRT_CONTEXT) {
            /* move data into context */
            if (analyzer->response_context)
                free(analyzer->response_context);
            analyzer->response_context = realloc(analyzer->response_data, analyzer->response_size + 1);
            if (analyzer->response_context) {
                /* realloc passed - remove from data and terminate */
                analyzer->response_context[analyzer->response_size] = 0;
                analyzer->response_data = NULL;
                analyzer->response_size = 0;
                analyzer->response_limit = 0;
            } /* else failed - keep as is - context null, data set */
        }
    } else {
        DWORD contentLen;
        size = sizeof(contentLen);
        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &contentLen, &size, WINHTTP_NO_HEADER_INDEX)) {
            /* content length read, adjust buffer as needed */
            if (analyzer->response_limit < contentLen) {
                if (analyzer->response_data)
                    free(analyzer->response_data);
                analyzer->response_size = 0;
                analyzer->response_data = malloc(contentLen);
                if (!analyzer->response_data) {
                    analyzer->response_limit = 0;
                    error = PVR_NOMEM;
                    goto error;
                }
                analyzer->response_limit = contentLen;
            }
        }

        /* read data */
        DWORD pos = 0;
        DWORD read;
        do {
            if (!WinHttpQueryDataAvailable(hRequest, &size))
                goto error;

            DWORD new_pos = pos + size;
            if (new_pos > analyzer->response_limit) {
                /* resize needed */
                char* new_data = realloc(analyzer->response_data, new_pos);
                if (!new_data) {
                    error = PVR_NOMEM;
                    goto error;
                }
                analyzer->response_data = new_data;
                analyzer->response_limit = new_pos;
            }
            if (!WinHttpReadData(hRequest, (LPVOID)(analyzer->response_data + pos), size, &read)) {
                goto error;
            }
            pos += read;
        } while (read > 0);
        analyzer->response_size = pos;

        if (result_type != PVRT_CONTEXT) {
            int context_len;
            int image_len = get_image_len(hRequest);
            context_len = analyzer->response_size - image_len;
            /* move context from body to analyzer and shorten data to contain only image */
            if (analyzer->response_context) {
                free(analyzer->response_context);
            }
            analyzer->response_context = calloc(context_len + 1, sizeof(char));
            if (!analyzer->response_context) {
                goto error;
            }
            if (!memcpy(analyzer->response_context, analyzer->response_data + image_len, context_len)) {
                goto error;
            }
            if (analyzer->response_context) {
                /* realloc passed - shorten data and terminate */
                analyzer->response_context[context_len] = '\0';
                analyzer->response_data[image_len] = '\0';
                analyzer->response_size = image_len;
                analyzer->response_limit = 0;
            }
        } else {
            /* move data into context */
            if (analyzer->response_context)
                free(analyzer->response_context);
            analyzer->response_context = realloc(analyzer->response_data, analyzer->response_size + 1);
            if (analyzer->response_context) {
                /* realloc passed - remove from data and terminate */
                analyzer->response_context[analyzer->response_size] = 0;
                analyzer->response_data = NULL;
                analyzer->response_size = 0;
                analyzer->response_limit = 0;
            } /* else failed - keep as is - context null, data set */
        }
    }

    /* fall through cleanup with no error */
    error = PVR_OK;

error:
    if (hRequest) {
        /* keep last error - close will reset it */
        DWORD lastError = GetLastError();
        WinHttpCloseHandle(hRequest);
        SetLastError(lastError);
    }
    if (path)
        free(path);
    return error;
}

int get_image_len(HINTERNET hRequest) {
    int image_len;
    DWORD size;
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CUSTOM, IMAGE_LEN_HEADER, WINHTTP_NO_OUTPUT_BUFFER, &size, WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        WORD *image_len_chars_couples = malloc(size);
        if (!image_len_chars_couples) {
            return PVR_NOMEM;
        }
        if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CUSTOM, IMAGE_LEN_HEADER, image_len_chars_couples, &size, WINHTTP_NO_HEADER_INDEX)) {
            return PVR_WINHTTP;
        }
        int new_size = size / sizeof(WORD);
        UCHAR *image_len_chars = calloc(new_size + 1, sizeof(UCHAR));
        if (!image_len_chars) {
            return PVR_NOMEM;
        }
        for (int i = 0; i < new_size; i++) {
            image_len_chars[i] = image_len_chars_couples[i];
        }
        image_len = atoi(image_len_chars);
        free(image_len_chars);
        free(image_len_chars_couples);
    }
    return image_len;
}

int pv_analyze_raw_image(pv_analyzer *analyzer, const char *image, int width, int height, pv_result_type result_type, const char *data) {
    wchar_t dim[50];
    swprintf_s(dim, sizeof(dim) / sizeof(wchar_t), L"&width=%d&height=%d", width, height);
    return pv_analyze_image_impl(analyzer, image, width * height * 3, result_type, data, L"/analyze_raw_image", dim);
}

int pv_analyze_image(pv_analyzer *analyzer, const char *image, int len, pv_result_type result_type, const char *data) {
    return pv_analyze_image_impl(analyzer, image, len, result_type, data, L"/analyze_image", NULL);
}

char* pv_get_result_data(pv_analyzer* analyzer) {
    return analyzer->response_size ? analyzer->response_data : NULL;
}

int pv_get_result_data_size(pv_analyzer* analyzer) {
    return(int)analyzer->response_size;
}

char* pv_get_result_context(pv_analyzer* analyzer) {
    return analyzer->response_context;
}
