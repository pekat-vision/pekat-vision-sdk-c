/* PEKAT VISION api                                                    */
/*                                                                     */
/* A .NET module for communication with PEKAT VISION 3.10.2 and higher */
/*                                                                     */
/* Author: developers@pekatvision.com                                  */
/* Date:   19 May 2022                                                 */
/* Web:    https://github.com/pekat-vision                             */

#include <curl/curl.h>

#include "sdk.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#if !CURL_AT_LEAST_VERSION(7, 62, 0)
#error "libcurl at least 7.62.0 is required"
#endif

#ifdef _WIN32
#define PATH_SEP "\\"
#define EXE_EXT ".exe"
#else
#define PATH_SEP "/"
#define EXE_EXT ""
#endif

#define SERVER_PATH (PATH_SEP "pekat_vision" PATH_SEP "pekat_vision" EXE_EXT)

/* todo: how long? */
/* in tenths of second (10 == 1 sec) */
#define START_WAIT_TIME 150
#define KILL_WAIT_TIME 50

#define CONTEXT_HEADER "ContextBase64utf:"
#define CONTENT_LENGTH_HEADER "Content-Length:"
#define IMAGE_LEN_HEADER "ImageLen:"

#define FROM_PORT 10000
#define TO_PORT 30000

struct _pv_analyzer {
    /* running process or 0 if none */
    pid_t pid;
    int stop_key;
    char *api_key;
    CURLU *url;
    CURL *curl;
    CURLcode curl_code;
    CURLUcode curlu_code;
    /* following are used while posting data */
    const char *request_data;
    int request_len;
    int request_pos;
    unsigned char context_in_body;
    /* following are filled in by response data */
    char *response_data;
    int response_limit;
    int response_pos;
    char *response_context;
    int image_len;
};

void pv_free_analyzer(pv_analyzer *analyzer) {
    if (analyzer->pid) {
        CURL *curl = NULL;
        CURLcode res;
        CURLUcode resu;
        char stop[50];
        int sent = 0;

        sprintf(stop, "key=%d", analyzer->stop_key);
        /* set path */
        resu = curl_url_set(analyzer->url, CURLUPART_PATH, "/stop", 0);
        if (resu)
            goto after_send;
        /* set query */
        resu = curl_url_set(analyzer->url, CURLUPART_QUERY, stop, 0);
        if (resu)
            goto after_send;
        /* create own curl as the one from analyzer has too many things set */
        curl = curl_easy_init();
        if (!curl)
            goto after_send;
        /* set url */
        res = curl_easy_setopt(curl, CURLOPT_CURLU, analyzer->url);
        if (res)
            goto after_send;
        /* prevent printing response to stdout - default behavior */
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
        /* send to server */
        res = curl_easy_perform(curl);
        if (res)
            goto after_send;
        /* send succeeded */
        sent = 1;
    after_send:
        if (curl)
            curl_easy_cleanup(curl);
        if (!sent) {
            /* send failed - kill instead */
            kill(analyzer->pid, SIGTERM);
        }
        /* wait some time for termination */
        for (int i = 0; !waitpid(analyzer->pid, NULL, WNOHANG) && i < KILL_WAIT_TIME; i++) {
            usleep(100000);
        }
        if (!waitpid(analyzer->pid, NULL, WNOHANG)) {
            /* forced kill */
            kill(analyzer->pid, SIGKILL);
        }
    }
    if (analyzer->api_key)
        free(analyzer->api_key);
    if (analyzer->response_data)
        free(analyzer->response_data);
    if (analyzer->response_context)
        free(analyzer->response_context);
    if (analyzer->url)
        curl_url_cleanup(analyzer->url);
    if (analyzer->curl)
        curl_easy_cleanup(analyzer->curl);
    free(analyzer);
}

static pv_analyzer *alloc_analyzer(const char *host, int port, const char *api_key) {
    pv_analyzer *analyzer;
    CURLcode res;
    CURLUcode resu;
    char port_str[6];

    if (!host || !*host || port <= 0 || port >= 65536)
        return NULL;
    sprintf(port_str, "%d", port);
    analyzer = malloc(sizeof(pv_analyzer));
    if (!analyzer)
        return NULL;
    analyzer->pid = 0;
    analyzer->api_key = NULL;
    analyzer->url = curl_url();
    analyzer->curl = curl_easy_init();
    analyzer->response_data = NULL;
    analyzer->response_limit = 0;
    analyzer->response_pos = 0;
    analyzer->image_len = 0;
    analyzer->response_context = NULL;
    analyzer->context_in_body = 0;
    if (!analyzer->url || !analyzer->curl)
        goto failed;
    if (api_key) {
        analyzer->api_key = malloc(strlen(api_key) + 9);
        if (!analyzer->api_key)
            goto failed;
        sprintf(analyzer->api_key, "api_key=%s", api_key);
    }
    /* fill url */
    resu = curl_url_set(analyzer->url, CURLUPART_SCHEME, "http", 0);
    if (resu)
        goto failed;
    resu = curl_url_set(analyzer->url, CURLUPART_HOST, host, 0);
    if (resu)
        goto failed;
    resu = curl_url_set(analyzer->url, CURLUPART_PORT, port_str, 0);
    if (resu)
        goto failed;
    /* assign url */
    res = curl_easy_setopt(analyzer->curl, CURLOPT_CURLU, analyzer->url);
    if (res)
        goto failed;

    return analyzer;

failed:
    pv_free_analyzer(analyzer);
    return NULL;
}

static int wait_server_start(pv_analyzer *analyzer) {
    CURLcode res;
    CURLUcode resu;

    /* set url */
    resu = curl_url_set(analyzer->url, CURLUPART_PATH, "/ping", 0);
    if (resu)
        return -1;

    /* prevent printing response to stdout - default behavior */
    curl_easy_setopt(analyzer->curl, CURLOPT_NOBODY, 1);

    /* wait for server start */
    for (int i = 0; i < START_WAIT_TIME; i++) {
        /* ping server */
        res = curl_easy_perform(analyzer->curl);
        if (!res) {
            /* check status code */
            long status;
            curl_easy_getinfo(analyzer->curl, CURLINFO_RESPONSE_CODE, &status);
            if (status == 200)
                return 0;
            /* any other status means failed */
            return -1;
        }

        /* not running process or process died - exit */
        if (!analyzer->pid || waitpid(analyzer->pid, NULL, WNOHANG)) {
            return -1;
            }

        /* sleep */
        usleep(100000);
    }
    return -1;
}

/* find two free consecutive ports */
static int find_port() {
    struct sockaddr_in addr;
    int s, res, last_port;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;

    last_port = 0;
    for (int p = FROM_PORT; p < TO_PORT; p++) {
        addr.sin_port = htons(p);
        s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0)
            return -1;
        res = bind(s, (struct sockaddr *)&addr, sizeof(addr));
        close(s);
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

pv_analyzer *pv_create_local_analyzer(const char *dist_path, const char *project_path, const char *api_key, char *const argv[]) {
    char *exe, port_str[6], stop[20];
    const char **args;
    int port, stop_key, argc;
    pid_t pid;
    pv_analyzer *analyzer;

    /* detect port */
    port = find_port();
    if (port == -1)
        return NULL;
    sprintf(port_str, "%d", port);

    /* generate stop key */
    srand((unsigned int)time(NULL));
    stop_key = rand();
    sprintf(stop, "%d", stop_key);
    /* prepare executable location */
    exe = malloc(strlen(dist_path) + strlen(SERVER_PATH) + 1);
    if (!exe)
        return NULL;
    strcat(strcpy(exe, dist_path), SERVER_PATH);

    /* prepare arguments */
    /* count: exe path, project (2x), host (2x), port (2x), stop key (2x), terminating NULL */
    argc = 10;
    if (api_key)
        argc += 2;
    if (argv) {
        for (char *const *a = argv; *a; a++, argc++);
    }
    args = malloc(argc * sizeof(char *));
    if (!args) {
        free(exe);
        return NULL;
    }
    args[0] = exe;
    args[1] = "-data";
    args[2] = project_path;
    args[3] = "-host";
    args[4] = "127.0.0.1";
    args[5] = "-port";
    args[6] = port_str;
    args[7] = "-stop_key";
    args[8] = stop;
    argc = 9;
    if (api_key) {
        args[argc++] = "-api_key";
        args[argc++] = api_key;
    }
    if (argv) {
        for (char *const *a = argv; (args[argc++] = *a++););
    } else {
        args[argc] = NULL;
    }

    /* allocate analyzer before exec so we don't have to kill process when alloc fails */
    analyzer = alloc_analyzer("127.0.0.1", port, api_key);
    if (!analyzer) {
        free(exe);
        free(args);
        return NULL;
    }

    /* run */
    pid = fork();
    if (!pid) {
        /* child */
        execv(exe, (char *const *)args);
        /* failed */
        perror("PekatVision server execution failed");
        exit(1);
    } else {
        /* parent */
        free(exe);
        free(args);
        if (pid == -1) {
            pv_free_analyzer(analyzer);
            return NULL;
        }
        analyzer->pid = pid;
        analyzer->stop_key = stop_key;
        if (wait_server_start(analyzer)) {
            pv_free_analyzer(analyzer);
            return NULL;
        }
        return analyzer;
    }
}

pv_analyzer *pv_create_remote_analyzer(const char *host, int port, const char *api_key) {
    pv_analyzer *analyzer = alloc_analyzer(host, port, api_key);
    if (!analyzer)
        return NULL;
    if (wait_server_start(analyzer)) {
        pv_free_analyzer(analyzer);
        return NULL;
    }
    return analyzer;
}

pv_analyzer *pv_clone_analyzer(pv_analyzer *orig) {
    pv_analyzer *analyzer;
    CURLUcode resu;
    char *host, *port_str;
    int port;

    resu = curl_url_get(orig->url, CURLUPART_HOST, &host, 0);
    if (resu)
        return NULL;
    resu = curl_url_get(orig->url, CURLUPART_PORT, &port_str, 0);
    if (resu) {
        curl_free(host);
        return NULL;
    }
    sscanf(port_str, "%d", &port);

    analyzer = alloc_analyzer(host, port, NULL);
    curl_free(host);
    curl_free(port_str);
    if (!analyzer)
        return NULL;
    /* set api key by copying */
    if (orig->api_key) {
        analyzer->api_key = strdup(orig->api_key);
        if (!analyzer->api_key) {
            pv_free_analyzer(analyzer);
            return NULL;
        }
    }
    return analyzer;
}

static size_t read_callback(char *buffer, size_t size, size_t nitems, void *userdata) {
    pv_analyzer *analyzer = (pv_analyzer *)userdata;
    int len = size * nitems;
    int rem = analyzer->request_len - analyzer->request_pos;
    if (rem < len)
        len = rem;
    memcpy(buffer, analyzer->request_data + analyzer->request_pos, len);
    analyzer->request_pos += len;
    return len;
}

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    pv_analyzer *analyzer = (pv_analyzer *)userdata;
    int len = size * nmemb;
    int new_pos = analyzer->response_pos + len;

    if (new_pos > analyzer->response_limit) {
        /* resize needed */
        char *new_data = realloc(analyzer->response_data, new_pos);
        if (!new_data)
            return 0;
        analyzer->response_data = new_data;
        analyzer->response_limit = new_pos;
    }
    memcpy(analyzer->response_data + analyzer->response_pos, ptr, len);
    analyzer->response_pos = new_pos;
    return len;
}

/* check if buffer matches header, return start of its value or 0 if no match */
static int check_header(char *buffer, int len, const char *header) {
    int hlen = strlen(header);
    if (len > hlen && !strncasecmp(buffer, header, hlen)) {
        for (int i = hlen; i < len; i++)
            if (buffer[i] == '\r' || buffer[i] == '\n')
                /* CR or LF - header end - treat as not found */
                return 0;
            else if (buffer[i] != ' ')
                /* non-space - value */
                return i;
    }
    return 0;
}

void pv_set_context_in_body(pv_analyzer *analyzer, unsigned char context_in_body) {
    analyzer->context_in_body = context_in_body;
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

static char *base64_decode(char *buffer, int len) {
    int tlen, accu;
    char *tbuffer;

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
    for (int i = 0, j = 0; j < tlen - 1; i++) {
        int b;
        char c = buffer[i];

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

static size_t header_callback(char *buffer, size_t size, size_t nitems, void *userdata) {
    pv_analyzer *analyzer = (pv_analyzer *)userdata;
    int len = size * nitems, i;

    i = check_header(buffer, len, CONTEXT_HEADER);
    if (i) {
        int e;
        /* find end */
        for (e = i; e < len && buffer[e] != '\r' && buffer[e] != '\n'; e++);
        /* decode */
        analyzer->response_context = base64_decode(buffer + i, e - i);
    }
    i = check_header(buffer, len, CONTENT_LENGTH_HEADER);
    if (i) {
        int l = 0;
        /* may have problems on non-ASCII platforms */
        for (; i < len && buffer[i] >= '0' && buffer[i] <= '9'; i++)
            l = l * 10 + buffer[i] - '0';
        if (l > 0) {
            if (analyzer->response_data)
                free(analyzer->response_data);
            analyzer->response_data = malloc(l);
            analyzer->response_limit = analyzer->response_data ? l : 0;
        }
    }
    i = check_header(buffer, len, IMAGE_LEN_HEADER);
    if (i) {
        int l = 0;
        for (; i < len && buffer[i] >= '0' && buffer[i] <= '9'; i++)
            l = l * 10 + buffer[i] - '0';
        analyzer->image_len = l;
    }
    return len;
}

/* must be in sync with response_type enum */
static char *response_types[] = { "response_type=context", "response_type=annotated_image", "response_type=heatmap" };

static int pv_analyze_image_impl(pv_analyzer *analyzer, const char *image, int len, pv_result_type result_type, const char *data, const char *path, const char *width, const char *height) {
    CURLcode res;
    CURLUcode resu;
    struct curl_slist *headers;
    long status;

    analyzer->curl_code = CURLE_OK;
    analyzer->curlu_code = CURLUE_OK;

    /* path */
    resu = curl_url_set(analyzer->url, CURLUPART_PATH, path, 0);
    if (resu)
        goto failed_url;
    /* remove query */
    resu = curl_url_set(analyzer->url, CURLUPART_QUERY, NULL, 0);
    if (resu)
        goto failed_url;
    /* response type - we cannot use without CURLU_APPENDQUERY to avoid setting NULL above since that will urlencode '=' sign */
    resu = curl_url_set(analyzer->url, CURLUPART_QUERY, response_types[result_type], CURLU_URLENCODE | CURLU_APPENDQUERY);
    if (resu)
        goto failed_url;
    /* api key */
    if (analyzer->api_key) {
        resu = curl_url_set(analyzer->url, CURLUPART_QUERY, analyzer->api_key, CURLU_URLENCODE | CURLU_APPENDQUERY);
        if (resu)
            goto failed_url;
    }
    /* width */
    if (width) {
        resu = curl_url_set(analyzer->url, CURLUPART_QUERY, width, CURLU_URLENCODE | CURLU_APPENDQUERY);
        if (resu)
            goto failed_url;
    }
    /* height */
    if (height) {
        resu = curl_url_set(analyzer->url, CURLUPART_QUERY, height, CURLU_URLENCODE | CURLU_APPENDQUERY);
        if (resu)
            goto failed_url;
    }
    /* context_in_body */
    if (analyzer->context_in_body) {
        resu = curl_url_set(analyzer->url, CURLUPART_QUERY, "context_in_body", CURLU_URLENCODE | CURLU_APPENDQUERY);
        if (resu)
            goto failed_url;
    }
    /* data */
    if (data) {
        char *d = malloc(strlen(data) + 6);
        if (!d) {
            return PVR_NOMEM;
        }
        sprintf(d, "data=%s", data);
        resu = curl_url_set(analyzer->url, CURLUPART_QUERY, d, CURLU_URLENCODE | CURLU_APPENDQUERY);
        free(d);
        if (resu)
            goto failed_url;
    }

    /* prepare data */
    res = curl_easy_setopt(analyzer->curl, CURLOPT_POST, 1L);
    if (res)
        goto failed_curl;
    res = curl_easy_setopt(analyzer->curl, CURLOPT_READFUNCTION, read_callback);
    if (res)
        goto failed_curl;
    res = curl_easy_setopt(analyzer->curl, CURLOPT_READDATA, analyzer);
    if (res)
        goto failed_curl;
    res = curl_easy_setopt(analyzer->curl, CURLOPT_POSTFIELDSIZE, (long)len);
    if (res)
        goto failed_curl;
    analyzer->request_data = image;
    analyzer->request_len = len;
    analyzer->request_pos = 0;
    /* headers */
    headers = curl_slist_append(NULL, "Content-Type: application/octet-stream");
    if (headers) {
        /* just ignore when list fails */
        res = curl_easy_setopt(analyzer->curl, CURLOPT_HTTPHEADER, headers);
        if (res)
            goto failed_curl;
    }
    /* response */
    res = curl_easy_setopt(analyzer->curl, CURLOPT_WRITEFUNCTION, write_callback);
    if (res)
        goto failed_curl;
    res = curl_easy_setopt(analyzer->curl, CURLOPT_WRITEDATA, analyzer);
    if (res)
        goto failed_curl;
    if (analyzer->response_context) {
        free(analyzer->response_context);
        analyzer->response_context = NULL;
    }
    analyzer->response_pos = 0;
    res = curl_easy_setopt(analyzer->curl, CURLOPT_HEADERFUNCTION, header_callback);
    if (res)
        goto failed_curl;
    res = curl_easy_setopt(analyzer->curl, CURLOPT_HEADERDATA, analyzer);
    if (res)
        goto failed_curl;

    /* do the post */
    res = curl_easy_perform(analyzer->curl);
    if (headers)
        curl_slist_free_all(headers);
    if (res)
        goto failed_curl;

    /* check status code */
    res = curl_easy_getinfo(analyzer->curl, CURLINFO_RESPONSE_CODE, &status);
    if (res)
        goto failed_curl;
    if (status != 200) {
        return (int)status;
    }

    if (result_type == PVRT_CONTEXT) {
        /* move data into context */
        if (analyzer->response_context)
            free(analyzer->response_context);
        analyzer->response_context = realloc(analyzer->response_data, analyzer->response_pos + 1);
        if (analyzer->response_context) {
            /* realloc passed - remove from data and terminate */
            analyzer->response_context[analyzer->response_pos] = 0;
            analyzer->response_data = NULL;
            analyzer->response_pos = 0;
            analyzer->response_limit = 0;
        } /* else failed - keep as is - context null, data set */
    }
    if (analyzer->context_in_body) {
        int context_len = analyzer->response_pos - analyzer->image_len;
        /* move context from body to analyzer and shorten data to contain only image */
        if (analyzer->response_context) {
            free(analyzer->response_context);
        }
        analyzer->response_context = calloc(context_len + 1, sizeof(char));
        if (!analyzer->response_context) {
            return PVR_NOMEM;
        }
        if (!memcpy(analyzer->response_context, analyzer->response_data + analyzer->image_len, context_len)) {
            return PVR_NOMEM;
        }
        analyzer->response_context[context_len] = '\0';
        analyzer->response_pos = analyzer->image_len;
        analyzer->response_limit = 0;
        analyzer->image_len = 0;
    }

    return PVR_OK;

failed_curl:
    analyzer->curl_code = res;
    return PVR_CURL;

failed_url:
    analyzer->curlu_code = resu;
    return PVR_CURLU;
}

int pv_analyze_raw_image(pv_analyzer *analyzer, const char *image, int width, int height, pv_result_type result_type, const char *data) {
    char w[32];
    char h[32];
    sprintf(w, "width=%d", width);
    sprintf(h, "height=%d", height);
    return pv_analyze_image_impl(analyzer, image, width * height * 3, result_type, data, "/analyze_raw_image", w, h);
}

int pv_analyze_image(pv_analyzer *analyzer, const char *image, int len, pv_result_type result_type, const char *data) {
    return pv_analyze_image_impl(analyzer, image, len, result_type, data, "/analyze_image", NULL, NULL);
}

char *pv_get_result_data(pv_analyzer *analyzer) {
    return analyzer->response_pos ? analyzer->response_data : NULL;
}

int pv_get_result_data_size(pv_analyzer *analyzer) {
    return analyzer->response_pos;
}

char *pv_get_result_context(pv_analyzer *analyzer) {
    return analyzer->response_context;
}

CURLcode pv_get_curl_code(pv_analyzer *analyzer) {
    return analyzer->curl_code;
}

CURLUcode pv_get_curlu_code(pv_analyzer *analyzer) {
    return analyzer->curlu_code;
}
