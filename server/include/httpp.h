#ifndef _HTTPP_HEADER
#define _HTTPP_HEADER

/*
 * Tiny header only http parser library for http 1/1 version.
 * To use this library:
 *      #define HTTPP_IMPLEMENTATION 
 *
 * Pipelined requests are not handled well because nobody really cares about them.
 * (https://en.wikipedia.org/wiki/HTTP_pipelining#Implementation_status)
 *
 * UPDATE:
 *   Chunked transfer should be handled on the server side by checking whenever the
 *   necessary header persist, based on that, do next steps. there is nothing
 *   the parser can do about it without bloating the code.
 *
 * UPDATE: 
 *   Folded headers will be rejected by this parser
 *
 * NOTE:
 *  By default httpp_parse_request, for the simplicity and speed, will use 
 *  sort of "Lazy" body splitting, meaning that whenever parser encounters 
 *  single "\r\n", it will handle anything after it as the body of 
 *  a request. This might not be desired behaviour in case if caller's buffer
 *  contains more than one request. If that's the case:
 *
 *  #define HTTPP_CONSIDER_CONTENT_LENGTH
 *
 *  This will make httpp_parse_request set body.length to the value 
 *  of Content-Length header with necessary bounds checks. This might
 *  suffer on performance a little bit.
 *
 *  Important note:
 *  This potentially introduces a missbehave: if Content-Length is bigger than
 *  the actual length of body and caller's buffer still has elements, then 
 *  beginning of the next potential request will be parsed as the body continuation 
 *  of the previous one. 
 * 
 * OPTIONS:
 *  By default httpp considers http version mismatch an error, to prevent this:
 *      #define HTTPP_DONT_CHECK_VERSION
 *  
 *  By default httpp will only remove first optional whitespace after header name.
 *  For general purpose it should be okay. If you want it to completely trim trailing
 *  and leading whitespaces from header values:
 *      #define HTTPP_TRIM_HEADER_VALUES
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
# include <strings.h>  /* strncasecmp (-std=c11) */
#endif

#define HTTPP_DEFAULT_HEADERS_ARR_CAP 20

#define HTTPP_SUPPORTED_VERSION "HTTP/1.1"
#define HTTPP_SUPPORTED_VERSION_LEN 8
#define HTTPP_MAX_METHOD_LENGTH 10

#define HTTPP_DELIMITER "\r\n"
#define HTTPP_DELIMITER_LEN 2
#define HTTPP_MAX_STATUS_CODE_LEN 3

#define HTTPP_METHOD_GET       0
#define HTTPP_METHOD_HEAD      1
#define HTTPP_METHOD_POST      2
#define HTTPP_METHOD_PUT       3
#define HTTPP_METHOD_DELETE    4
#define HTTPP_METHOD_CONNECT   5
#define HTTPP_METHOD_OPTIONS   6
#define HTTPP_METHOD_TRACE     7
#define HTTPP_METHOD_PATCH     8
#define HTTPP_METHOD_UNKNOWN  -1

#define httpp_string_to_method(s) ( strcmp((s), "GET")     == 0 ? HTTPP_METHOD_GET    : \
                                    strcmp((s), "HEAD")    == 0 ? HTTPP_METHOD_HEAD   : \
                                    strcmp((s), "POST")    == 0 ? HTTPP_METHOD_POST   : \
                                    strcmp((s), "PUT")     == 0 ? HTTPP_METHOD_PUT    : \
                                    strcmp((s), "DELETE")  == 0 ? HTTPP_METHOD_DELETE : \
                                    strcmp((s), "CONNECT") == 0 ? HTTPP_METHOD_CONNECT: \
                                    strcmp((s), "OPTIONS") == 0 ? HTTPP_METHOD_OPTIONS: \
                                    strcmp((s), "TRACE")   == 0 ? HTTPP_METHOD_TRACE  : \
                                    strcmp((s), "PATCH")   == 0 ? HTTPP_METHOD_PATCH  : \
                                                                  HTTPP_METHOD_UNKNOWN) \

typedef struct {
    char* ptr;
    size_t length;
    bool is_owned;
} httpp_span_t;

typedef struct {
    httpp_span_t name;
    httpp_span_t value;
} httpp_header_t;

typedef struct {
    httpp_header_t* arr;
    size_t capacity;
    size_t length;
} httpp_headers_arr_t;

typedef struct {
    httpp_headers_arr_t headers;
    httpp_span_t body;
    httpp_span_t route;
    httpp_span_t version;
    int method;
} httpp_req_t;

typedef struct {
    httpp_headers_arr_t headers;
    httpp_span_t body;
    int code;
} httpp_res_t;

typedef struct {
    char*  raw;
    size_t raw_len;
} httpp_raw_res_t;

const char* httpp_method_to_string(int method);
const char* httpp_status_to_string(int status_code);

// Converts httpp_span_t to a malloc'd string. Caller must free 
char* httpp_span_to_str(httpp_span_t span);

// Checks is httpp_span_t equal to `to` 
bool httpp_span_eq(httpp_span_t span, const char* to);

// Checks is httpp_span_t equal to `to` without case considering
bool httpp_span_case_eq(httpp_span_t span, const char* to);

/*
 * Parses the raw http request passed as `buf`. 
 *   On failure returns -1.
 * 
 * On sucess returns offset from the beginning of `buf` to 
 * the beginning of the dest->body.
 */
int httpp_parse_request(char* buf, size_t n, httpp_req_t* dest);

/* 
 * Parses http request start line.
 * http version mismatch is considered a failure
 *   On failure returns -1. 
 *
 * On sucess returns offset from the beginning of `buf` to
 * the end of the start line
 */ 
int httpp_parse_start_line(char* buf, size_t n, httpp_req_t* dest);

/*
 * Parses http header string and appends it to `dest`
 *   On failure returns NULL
 * 
 * `content_len` must be a length of the content of the line, meaning it 
 * should not include the length of "\r\n", length of actual content only
 * 
 * On sucess returns a pointer to the last header in `dest` 
 */
httpp_header_t* httpp_parse_header(httpp_headers_arr_t* dest, char* line, size_t content_len);

// Appends `header` to `hs`, On failure returns NULL, on sucess returns pointer to last header
httpp_header_t* httpp_headers_arr_append(httpp_headers_arr_t* hs, httpp_header_t header);

// Searches for a header with `name` in `hs`, On failure returns NULL, on sucess returns pointer to it
httpp_header_t* httpp_headers_arr_find(httpp_headers_arr_t* hs, const char* name);

// Converts `res` to it's malloc'd raw string representation. Sets final raw length to `out_len`
char* httpp_res_to_raw(httpp_res_t* res, size_t* out_len);

// Creates new header with strdupped name and value, and appends it to `res->headers`
httpp_header_t* httpp_res_add_header(httpp_res_t* res, const char* name, const char* value);

// Frees strdupped by httpp_res_add_header headers from `res` 
void httpp_res_free_added(httpp_res_t* res);

#define httpp_find_header(req_or_res, name) \
    (httpp_headers_arr_find(&(req_or_res).headers, name))

#define httpp_res_set_body(res, body_ptr, body_len) \
   (res.body = (httpp_span_t){body_ptr, body_len, false})

#define HTTPP_NEW_REQ(name) \
    httpp_req_t name; \
    httpp_init_req(&name, HTTPP_DEFAULT_HEADERS_ARR_CAP)

#define HTTPP_NEW_RES(name, status) \
    httpp_res_t name; \
    httpp_init_res(&name, HTTPP_DEFAULT_HEADERS_ARR_CAP, status)

static inline void httpp_init_span(httpp_span_t* span) 
{
    span->ptr = NULL;
    span->length = 0;
    span->is_owned = false;
}

static inline void httpp_init_req(
    httpp_req_t* dest, size_t headers_capacity)
{
    httpp_init_span(&dest->route);
    httpp_init_span(&dest->body);

    dest->headers.capacity = headers_capacity;
    dest->headers.length = 0;
    dest->headers.arr = (httpp_header_t*) malloc(sizeof(httpp_header_t) * headers_capacity);
}

static inline void httpp_init_res(
    httpp_res_t* dest, size_t headers_capacity, int status_code)
{
    dest->code = status_code;
    dest->headers.capacity = headers_capacity;
    dest->headers.length = 0;
    dest->headers.arr = (httpp_header_t*) malloc(sizeof(httpp_header_t) * headers_capacity);
}

#ifdef HTTPP_IMPLEMENTATION

// Originial isspace is kinda slow...
#define __ISSPACE(c) ( (((c) == ' ') || ((c) == '\r') || ((c) == '\n') || ((c) == '\t')) )

#define LTRIM(str, len) do {                                \
    while ((len) > 0) {                                     \
        if (!__ISSPACE(*str))                               \
            break;                                          \
        (str)++;                                            \
        (len)--;                                            \
    }                                                       \
} while (0)

#define RTRIM(str, len) do {                                \
    while ((len) > 0) {                                     \
        if (!__ISSPACE((str)[(len) - 1]))                   \
            break;                                          \
        (len)--;                                            \
    }                                                       \
} while (0)

#define SETSTR(dest, src, len) do { \
        memcpy(dest, (src), (len)); \
        dest[(len)] = '\0';         \
    } while (0)

static char* __strdup(const char* str) 
{
    if (!str)
        return NULL;

    size_t n = strlen(str) + 1;

    char* dupped = (char*) malloc(n);
    if (!dupped)
        return NULL;

    memcpy(dupped, str, n);
    return dupped;
}

const char* httpp_method_to_string(int method) 
{
    switch (method) {
        case HTTPP_METHOD_GET:      return "GET";
        case HTTPP_METHOD_HEAD:     return "HEAD";
        case HTTPP_METHOD_POST:     return "POST";
        case HTTPP_METHOD_PUT:      return "PUT";
        case HTTPP_METHOD_DELETE:   return "DELETE";
        case HTTPP_METHOD_CONNECT:  return "CONNECT";
        case HTTPP_METHOD_OPTIONS:  return "OPTIONS";
        case HTTPP_METHOD_TRACE:    return "TRACE";
        case HTTPP_METHOD_PATCH:    return "PATCH";

        case HTTPP_METHOD_UNKNOWN:
        default:                    return "UNKNOWN";
    }
}

const char* httpp_status_to_string(int status_code) 
{
    switch (status_code) {
        // Informational
        case 100: return "Continue";
        case 101: return "Switching Protocols";
        case 102: return "Processing";
        case 103: return "Early Hints";

        // Successful
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 203: return "Non-Authoritative Information";
        case 204: return "No Content";
        case 205: return "Reset Content";
        case 206: return "Partial Content";
        case 207: return "Multi-Status";
        case 208: return "Already Reported";
        case 226: return "IM Used";

        // Redirection
        case 300: return "Multiple Choices";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 305: return "Use Proxy";
        case 306: return "Unused";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";

        // Client Error
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 402: return "Payment Required";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 406: return "Not Acceptable";
        case 407: return "Proxy Authentication Required";
        case 408: return "Request Timeout";
        case 409: return "Conflict";
        case 410: return "Gone";
        case 411: return "Length Required";
        case 412: return "Precondition Failed";
        case 413: return "Content Too Large";
        case 414: return "URI Too Long";
        case 415: return "Unsupported Media Type";
        case 416: return "Range Not Satisfiable";
        case 417: return "Expectation Failed";
        case 418: return "I'm a teapot";
        case 421: return "Misdirected Request";
        case 422: return "Unprocessable Content";
        case 423: return "Locked";
        case 424: return "Failed Dependency";
        case 425: return "Too Early";
        case 426: return "Upgrade Required";
        case 428: return "Precondition Required";
        case 429: return "Too Many Requests";
        case 431: return "Request Header Fields Too Large";
        case 451: return "Unavailable For Legal Reasons";

        // Server Error 
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        case 505: return "HTTP Version Not Supported";
        case 506: return "Variant Also Negotiates";
        case 507: return "Insufficient Storage";
        case 508: return "Loop Detected";
        case 510: return "Not Extended";
        case 511: return "Network Authentication Required";

        case -1:
        default: return "Unspecified";
    }
}

char* httpp_span_to_str(httpp_span_t span)
{
    char* out = (char*) malloc(span.length + 1);

    if (!out)
        return NULL;
    
    SETSTR(out, span.ptr, span.length);
    return out;
}

bool httpp_span_eq(httpp_span_t span, const char* to)
{
    if (!span.ptr || to == NULL) 
        return false;
    
    size_t expected = strlen(to);

    if (span.length != expected) 
        return false;

    return (strncmp(span.ptr, to, expected) == 0);
}

bool httpp_span_case_eq(httpp_span_t span, const char* to) 
{
    if (!span.ptr || to == NULL) 
        return false;
    
    size_t expected = strlen(to);

    if (span.length != expected) 
        return false;

    return (strncasecmp(span.ptr, to, expected) == 0);
}

httpp_header_t* httpp_headers_arr_append(httpp_headers_arr_t* hs, httpp_header_t header)
{
    if (!header.name.ptr || !header.value.ptr) 
        return NULL; // Value is empty

    if (hs->length >= hs->capacity) {
        size_t new_cap = hs->capacity ? hs->capacity * 2 : 4; 
        
        if (new_cap < hs->capacity)
            return NULL;

        httpp_header_t* tmp = (httpp_header_t*) realloc(hs->arr, sizeof(httpp_header_t) * new_cap);

        if (!tmp) 
            return NULL;

        hs->arr = tmp;
        hs->capacity = new_cap;
    }


    hs->arr[hs->length++] = header;
    return &hs->arr[hs->length - 1];
}

httpp_header_t* httpp_headers_arr_find(httpp_headers_arr_t* hs, const char* name)
{
    // For the sake of simplicity and minimalism, it's just a for loop. No hash table here.
    size_t name_len = strlen(name);

    for (size_t i = 0; i < hs->length; i++) {
        httpp_span_t posible = hs->arr[i].name;

        if (posible.length != name_len)
            continue;

        if (strncasecmp(posible.ptr, name, posible.length) == 0)
            return &hs->arr[i];
    }

    return NULL;
}


httpp_header_t* httpp_res_add_header(httpp_res_t* res, const char* name, const char* value)
{
    if (!name || !value) 
        return NULL;
    
    char* mname = __strdup(name);
    if (!mname)
        return NULL;

    char* mvalue = __strdup(value);
    if (!mvalue) {
        free(mname);
        return NULL;
    }

    httpp_header_t h = {
        {mname, strlen(name), true}, 
        {mvalue, strlen(value), true}
    };

    httpp_header_t* out = httpp_headers_arr_append(&res->headers, h);

    if (out == NULL) {
        free(h.name.ptr);
        free(h.value.ptr);
    } 

    return out;
}

void httpp_res_free_added(httpp_res_t* res)
{
    for (size_t i = 0; i < res->headers.length; i++) {
        if (res->headers.arr[i].name.is_owned)
            free(res->headers.arr[i].name.ptr);

        if (res->headers.arr[i].value.is_owned)
            free(res->headers.arr[i].value.ptr);
    }
}

static inline char* chop(char until, httpp_span_t* to, char* from, size_t from_len) 
{
    to->ptr = from;
    char* delim = (char*) memchr(from, until, from_len);

    if (!delim)
        return NULL;

    to->length = delim - to->ptr;
    return delim + 1;
}

int httpp_parse_start_line(char* buf, size_t n, httpp_req_t* dest)
{
    httpp_span_t route = {.is_owned = false};
    httpp_span_t version = {.is_owned = false};

    char  method_buf[HTTPP_MAX_METHOD_LENGTH + 1];
    char* itr = buf;
    char* delim;

    delim = (char*) memchr(itr, ' ', n);
    if (!delim)
        return -1;

    if (delim - itr >= HTTPP_MAX_METHOD_LENGTH + 1)
        return -1;

    SETSTR(method_buf, itr, delim - itr);
    itr = delim + 1;

    if ((itr = chop(' ', &route, itr, n - (itr - buf))) == NULL)
        return -1;
    
    if ((itr = chop('\r', &version, itr, n - (itr - buf))) == NULL)
        return -1;
    
    if (itr >= buf + n)
        return -1;

    if (*itr != '\n')
        return -1;

    itr++;

    if (version.length != HTTPP_SUPPORTED_VERSION_LEN)
        return -1;

#ifndef HTTPP_DONT_CHECK_VERSION
    if (strncmp(version.ptr, HTTPP_SUPPORTED_VERSION, version.length) != 0)
        return -1;
#endif

    dest->method = httpp_string_to_method(method_buf);
    dest->version = version;
    dest->route = route;

    return (itr - buf);
}

httpp_header_t* httpp_parse_header(httpp_headers_arr_t* dest, char* line, size_t content_len)
{
    // RFC says that header starting with whitespace or any other non printable ascii should be rejected.
    if (__ISSPACE(*line))
        return NULL;

    char* colon = (char*) memchr(line, ':', content_len);
    if (!colon)
        return NULL;

    size_t name_len = colon - line;

    char* value_start = colon + 1;
    size_t value_len = content_len - name_len - 1;

#ifdef HTTPP_TRIM_HEADER_VALUES
    LTRIM(value_start, value_len);
    RTRIM(value_start, value_len);
#else
    // Skip only first optional space
    if (value_len > 0 && __ISSPACE(*value_start)) {
        value_start++;
        value_len--;
    }
#endif

    if (value_len > content_len)
        return NULL; // Just in case

    httpp_span_t name = {line, name_len, false};
    httpp_span_t value = {value_start, value_len, false};

    return httpp_headers_arr_append(dest, (httpp_header_t){name, value});
}

int httpp_parse_request(char* buf, size_t n, httpp_req_t* dest)
{
    if (buf == NULL || dest == NULL)
        return -1;
    
    if (n == 0)
        return 0;

    char* itr = buf;
    char* end = buf + n;
    int   off;

#ifdef HTTPP_CONSIDER_CONTENT_LENGTH
    size_t content_len = 0;
#endif

    if ((off = httpp_parse_start_line(itr, n, dest)) == -1)
        return -1;

    itr += off;
    while (itr < end) {
        httpp_header_t* parsed;
        char* delim = strstr(itr, HTTPP_DELIMITER);
        
        if (!delim)
            break;
        
        size_t line_size = delim - itr;
        if (line_size == 0) {
            itr = delim + HTTPP_DELIMITER_LEN;
            break;
        }

        if ((parsed = httpp_parse_header(&dest->headers, itr, line_size)) == NULL)
            return -1;

#ifdef HTTPP_CONSIDER_CONTENT_LENGTH
        if (httpp_span_case_eq(parsed->name, "content-length")) {
            char* val = httpp_span_to_str(parsed->value);
            content_len = atol(val);
            free(val);
        }
#endif
        itr = delim + HTTPP_DELIMITER_LEN;
    }

    dest->body.ptr = itr; // Itr now points at the beginning of the body

#ifdef HTTPP_CONSIDER_CONTENT_LENGTH
    if (content_len <= n - (itr - buf))
        dest->body.length = content_len;
    else
        return -1;
#else
    dest->body.length = n - (itr - buf);
#endif

    return itr - buf;
}

char* httpp_res_to_raw(httpp_res_t* res, size_t* out_len)
{
    if (res == NULL)
        return NULL; 

    if (res->code == -1 || res->code > 600)
        return NULL;

    const char* status_msg = httpp_status_to_string(res->code);
    size_t out_size =  
        strlen(HTTPP_SUPPORTED_VERSION) 
        + 1 // Space
        + HTTPP_MAX_STATUS_CODE_LEN
        + 1 // Space
        + strlen(status_msg)
        + HTTPP_DELIMITER_LEN;

    for (size_t i = 0; i < res->headers.length; i++) {
        httpp_header_t header = res->headers.arr[i];
        
        if (!header.name.ptr || !header.value.ptr)
            continue;

        out_size += header.name.length + 2 // ": "
                  + header.value.length 
                  + HTTPP_DELIMITER_LEN;
    }

    out_size += HTTPP_DELIMITER_LEN;
    out_size += res->body.length;
    out_size += 1; // '\0'

    char* out = (char*) malloc(out_size);
    if (!out)
        return NULL;

    int written = snprintf(out, out_size, "%s %d %s\r\n", HTTPP_SUPPORTED_VERSION, res->code, status_msg);
    if (written < 0 || (size_t) written >= out_size) {
        free(out);
        return NULL;
    }

    size_t offset = written;

    for (size_t i = 0; i < res->headers.length; i++) {
        httpp_header_t header = res->headers.arr[i];
        if (!header.name.ptr || !header.value.ptr)
            continue;

        int n = snprintf(out + offset, out_size - offset, 
                    "%s: %s\r\n", header.name.ptr, header.value.ptr);

        if (n < 0 || (size_t) n >= out_size - offset) {
            free(out);
            return NULL;
        }

        offset += n;
    }

    strcat(out, HTTPP_DELIMITER);

    if (res->body.length) {
        char* end = out + offset + HTTPP_DELIMITER_LEN;
        SETSTR(end, res->body.ptr, res->body.length);
    }

    if (out_len)  
        *out_len = out_size - 1; // no '\0'

    return out;
}

#endif // HTTPP_IMPLEMENTATION
#endif // _HTTPP_HEADER

/*
* MIT License
* 
* Copyright (c) 2025 Mint
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/