/*

Hydra Form Module
-----------------

The hydra form can be used to carry out a brute-force attack on simple
web-based login forms that require username and password variables via
either a GET or POST request.

The module works similarly to the HTTP basic auth module and will honour
proxy mode (with authenticaion) as well as SSL. The module can be invoked
with the service names of "http-get-form", "http-post-form",
"https-get-form" and "https-post-form".

Here's a couple of examples: -

./hydra -l "<userID>" -P pass.txt 10.221.64.12 http-post-form
"/irmlab2/testsso-auth.do:ID=^USER^&Password=^PASS^:Invalid Password"

./hydra -S -s 443 -l "<username>" -P pass.txt 10.221.64.2 https-get-form
"/irmlab1/vulnapp.php:username=^USER^&pass=^PASS^:incorrect"

The option field (following the service field) takes three ":" separated
values and an optional fourth value, the first is the page on the server
to GET or POST to, the second is the POST/GET variables (taken from either
the browser, or a proxy such as PAROS) with the varying usernames and passwords
in the "^USER^" and "^PASS^" placeholders, the third is the string that it
checks for an *invalid* or *valid* login - any exception to this is counted
as a success.
So please:
 * invalid condition login should be preceded by "F="
 * valid condition login should be preceded by "S=".
By default, if no header is found the condition is assume to be a fail,
so checking for *invalid* login.
The fourth optional value, can be a 'C' to define a different page to GET
initial cookies from.

If you specify the verbose flag (-v) it will show you the response from the
HTTP server which is useful for checking the result of a failed login to
find something to pattern match against.

Module initially written by Phil Robinson, IRM Plc (releases@irmplc.com),
rewritten by David Maciejak

Fix and issue with strtok use and implement 1 step location follow if HTTP
3xx code is returned (david dot maciejak at gmail dot com)

Added fail or success condition, getting cookies, and allow 5 redirections by
david

*/

#include "hydra-http.h"
#include "sasl.h"

extern char *HYDRA_EXIT;
char *buf;
char *cond;
extern int32_t http_auth_mechanism;

struct header_node {
  char *header;
  char *value;
  char type;
  struct header_node *next;
};

typedef struct cookie_node {
  char *name;
  char *value;
  struct cookie_node *prev;
  struct cookie_node *next;
} t_cookie_node, *ptr_cookie_node;

int32_t success_cond = 0;
int32_t getcookie = 1;
int32_t auth_flag = 0;
int32_t code_302_is_success = 0;

char cookie[4096] = "", cmiscptr[1024];

int32_t webport;
char bufferurl[6096 + 24], cookieurl[6096 + 24] = "", userheader[6096 + 24] = "", *url, *variables, *optional1;

#define MAX_REDIRECT 8
#define MAX_CONTENT_LENGTH 20
#define MAX_PROXY_LENGTH 2048 // sizeof(cookieurl) * 2

char redirected_url_buff[2048] = "";
int32_t redirected_flag = 0;
int32_t redirected_cpt = MAX_REDIRECT;

char *cookie_request = NULL, *normal_request = NULL; // Buffers for HTTP headers

/*
 * Function to perform some initial setup.
 */
ptr_header_node initialize(char *ip, unsigned char options, char *miscptr);

/*
 * Returns 1 if specified header exists, or 0 otherwise.
 */
ptr_header_node header_exists(ptr_header_node *ptr_head, char *header_name, char type) {
  ptr_header_node cur_ptr = *ptr_head, found_header = NULL;

  for (cur_ptr = *ptr_head; cur_ptr && !found_header; cur_ptr = cur_ptr->next)
    if (cur_ptr->header && strcmp(cur_ptr->header, header_name) == 0 && cur_ptr->type == type)
      found_header = cur_ptr;

  return found_header;
}

#if defined(__sun)

/* Written by Kaveh R. Ghazi <ghazi@caip.rutgers.edu> */
char *strndup(const char *s, size_t n) {
  char *result;
  size_t len = strlen(s);

  if (n < len)
    len = n;

  result = (char *)malloc(len + 1);
  if (!result)
    return 0;

  memcpy(result, s, len);
  result[len] = '\0';
  return (result);
}
#endif

int32_t append_cookie(char *name, char *value, ptr_cookie_node *last_cookie) {
  ptr_cookie_node new_ptr = (ptr_cookie_node)malloc(sizeof(t_cookie_node));

  if (!new_ptr)
    return 0;
  new_ptr->name = name;
  new_ptr->value = value;
  new_ptr->next = NULL;
  new_ptr->prev = NULL;

  if (*last_cookie == NULL)
    *last_cookie = new_ptr;
  else
    (*last_cookie)->next = new_ptr;

  return 1;
}

char *stringify_cookies(ptr_cookie_node ptr_cookie) {
  ptr_cookie_node cur_ptr = NULL;
  uint32_t length = 1;
  char *cookie_hdr = (char *)malloc(length);

  if (cookie_hdr) {
    memset(cookie_hdr, 0, length);
    for (cur_ptr = ptr_cookie; cur_ptr; cur_ptr = cur_ptr->next) {
      length += 2 + strlen(cur_ptr->name) + strlen(cur_ptr->value);
      cookie_hdr = (char *)realloc(cookie_hdr, length);
      if (cookie_hdr) {
        strcat(cookie_hdr, cur_ptr->name);
        strcat(cookie_hdr, "=");
        strcat(cookie_hdr, cur_ptr->value);
        if (cur_ptr->next)
          strcat(cookie_hdr, ";");
      } else
        goto bail;
    }
    goto success;
  }

bail:
  if (cookie_hdr) {
    free(cookie_hdr);
    cookie_hdr = NULL;
  }

success:
  return cookie_hdr;
}

/*
 * Cookie list layout:
 * 	+----------+     +--------+     +------+
 * 	| ptr_head | --> | next   | --> | NULL |
 * 	+----------+     | header |     +------+
 * 	                 | value  |
 * 	                 +--------+
 * Returns 1 if success, or 0 otherwise.
 */
int32_t add_or_update_cookie(ptr_cookie_node *ptr_cookie, char *cookie_expr) {
  ptr_cookie_node cur_ptr = NULL;
  char *cookie_name = NULL, *cookie_value = strstr(cookie_expr, "=");

  if (cookie_value) {
    cookie_name = strndup(cookie_expr, cookie_value - cookie_expr);
    cookie_value = strdup(cookie_value + 1);

    // we've got the cookie's name and value, now it's time to insert or update
    // the list
    if (*ptr_cookie == NULL) {
      // no cookies
      append_cookie(cookie_name, cookie_value, ptr_cookie);
    } else {
      for (cur_ptr = *ptr_cookie; cur_ptr; cur_ptr = cur_ptr->next) {
        if (strcmp(cur_ptr->name, cookie_name) == 0) {
          free(cur_ptr->value); // free old value
          free(cookie_name);    // we already have it
          cur_ptr->value = cookie_value;
          break;
        }
        if (cur_ptr->next == NULL) {
          append_cookie(cookie_name, cookie_value, &cur_ptr);
          break;
        }
      }
    }
  } else
    return 0;
  return 1;
}

int32_t process_cookies(ptr_cookie_node *ptr_cookie, char *cookie_expr) {
  char *tok = NULL;
  char *expr = strdup(cookie_expr);
  int32_t res = 0;

  if (strstr(cookie_expr, ";")) {
    tok = strtok(expr, ";");
    while (tok) {
      res = add_or_update_cookie(ptr_cookie, tok);
      if (!res) {
        free(expr);
        return res;
      }
      tok = strtok(NULL, ";");
    }
    free(expr);
    return res;
  } else {
    add_or_update_cookie(ptr_cookie, expr);
    free(expr);
    return 0;
  }
}

/*
 * List layout:
 * 	+----------+     +--------+     +--------+     +--------+
 * 	| ptr_head | --> |  next  | --> |  next  | --> |  NULL  |
 * 	|          |     | header |     | header |     |  NULL  |
 * 	|          |     | value  |     |  value |     |  NULL  |
 * 	+----------+     +--------+     +--------+     +--------+
 *
 * 	Returns 1 if success, or 0 otherwise (out of memory).
 */
int32_t add_header(ptr_header_node *ptr_head, char *header, char *value, char type) {
  ptr_header_node cur_ptr = NULL;
  ptr_header_node existing_hdr, new_ptr;

  if (!header || !value || !strlen(header) || !strlen(value))
    return 0;

  // get to the last header
  for (cur_ptr = *ptr_head; cur_ptr && cur_ptr->next; cur_ptr = cur_ptr->next)
    ;

  char *new_header = strdup(header);
  char *new_value = strdup(value);

  if (new_header && new_value) {
    if ((type == HEADER_TYPE_USERHEADER) || (type == HEADER_TYPE_DEFAULT && !header_exists(ptr_head, new_header, HEADER_TYPE_USERHEADER_REPL)) || (type == HEADER_TYPE_USERHEADER_REPL && !header_exists(ptr_head, new_header, HEADER_TYPE_DEFAULT)) || (type == HEADER_TYPE_DEFAULT_REPL && !header_exists(ptr_head, new_header, HEADER_TYPE_DEFAULT))) {
      /*
       * We are in one of the following scenarios:
       *      1. A default header with no user-supplied headers that replace it.
       *      2. A user-supplied header that must be appended (option 'h').
       *      3. A user-supplied header that must replace a default header
       * (option 'h'), but no default headers exist with that name.
       *
       * In either case we just add the header to the list.
       */
      new_ptr = (ptr_header_node)malloc(sizeof(t_header_node));
      if (!new_ptr) {
        free(new_header);
        free(new_value);
        return 0;
      }
      new_ptr->header = new_header;
      new_ptr->value = new_value;
      new_ptr->type = type;
      new_ptr->next = NULL;

      if (cur_ptr)
        cur_ptr->next = new_ptr;
      else {
        // head is NULL, so the list is empty
        *ptr_head = new_ptr;
      }
    } else if ((type == HEADER_TYPE_DEFAULT_REPL || type == HEADER_TYPE_USERHEADER_REPL) && (existing_hdr = header_exists(ptr_head, new_header, HEADER_TYPE_DEFAULT)) != NULL) {
      // It's a user-supplied header that must replace a default one
      // Replace the default header's value with this new value
      free(existing_hdr->value); // free old value
      existing_hdr->value = new_value;
      existing_hdr->type = type;
      free(new_header); // we dont need this one anymore
    }
  } else {
    // we're out of memory, so forcefully end
    free(new_header);
    free(new_value);
    return 0;
  }

  return 1;
}

/*
 * Replace in all headers' values every occurrence of oldvalue by newvalue.
 * Only user-defined headers are considered.
 */
void hdrrep(ptr_header_node *ptr_head, char *oldvalue, char *newvalue) {
  ptr_header_node cur_ptr = NULL;

  for (cur_ptr = *ptr_head; cur_ptr; cur_ptr = cur_ptr->next) {
    if ((cur_ptr->type == HEADER_TYPE_USERHEADER || cur_ptr->type == HEADER_TYPE_USERHEADER_REPL) && strstr(cur_ptr->value, oldvalue)) {
      cur_ptr->value = (char *)realloc(cur_ptr->value, strlen(newvalue) + 1);
      if (cur_ptr->value)
        strcpy(cur_ptr->value, newvalue);
      else {
        hydra_report(stderr, "[ERROR] Out of memory (hddrep).\n");
        hydra_child_exit(0);
      }
    }
  }
}

/*
 * Replace the value of the default header named 'hdrname'.
 */
void hdrrepv(ptr_header_node *ptr_head, char *hdrname, char *new_value) {
  ptr_header_node cur_ptr = NULL;

  for (cur_ptr = *ptr_head; cur_ptr; cur_ptr = cur_ptr->next) {
    if ((cur_ptr->type == HEADER_TYPE_DEFAULT) && strcmp(cur_ptr->header, hdrname) == 0) {
      cur_ptr->value = (char *)realloc(cur_ptr->value, strlen(new_value) + 1);
      if (cur_ptr->value)
        strcpy(cur_ptr->value, new_value);
      else {
        hydra_report(stderr, "[ERROR] Out of memory (hdrrepv %lu)\n", strlen(new_value) + 1);
        hydra_child_exit(0);
      }
    }
  }
}

void cleanup(ptr_header_node *ptr_head) {
  ptr_header_node cur_ptr = *ptr_head, next_ptr = cur_ptr;

  while (next_ptr != NULL) {
    free(cur_ptr->header);
    free(cur_ptr->value);
    next_ptr = cur_ptr->next;
  }

  *ptr_head = NULL;
}

/*
 * Concat all the headers in the list in a single string.
 * Leave the list itself intact: do not clean it here.
 */
char *stringify_headers(ptr_header_node *ptr_head) {
  char *headers_str = NULL;
  ptr_header_node cur_ptr = *ptr_head;
  int32_t ttl_size = 0;

  for (; cur_ptr; cur_ptr = cur_ptr->next)
    ttl_size += strlen(cur_ptr->header) + strlen(cur_ptr->value) + 4;

  headers_str = (char *)malloc(ttl_size + 1);

  if (headers_str) {
    memset(headers_str, 0, ttl_size + 1);
    for (cur_ptr = *ptr_head; cur_ptr; cur_ptr = cur_ptr->next) {
      strcat(headers_str, cur_ptr->header);
      strcat(headers_str, ": ");
      strcat(headers_str, cur_ptr->value);
      strcat(headers_str, "\r\n");
    }
  }

  return headers_str;
}

int32_t parse_options(char *miscptr, ptr_header_node *ptr_head) {
  char *ptr, *ptr2;

  if (miscptr == NULL)
    return 1;

  /*
   * Parse the user-supplied options.
   * Beware of the backslashes (\)!
   */
  while (*miscptr != 0) {
    if (strlen(miscptr) < 2 || miscptr[1] != '=') {
      hydra_report(stderr, "[ERROR] optional parameters must have the format X=value: %s\n", miscptr);
      return 0;
    }
    switch (miscptr[0]) {
    case 'a': // fall through
    case 'A': // only for http, not http-form!
      ptr = miscptr + 2;

      if (strncasecmp(ptr, "NTLM", 4) == 0)
        http_auth_mechanism = AUTH_NTLM;
      else if (strncasecmp(ptr, "MD5", 3) == 0 || strncasecmp(ptr, "DIGEST", 6) == 0)
        http_auth_mechanism = AUTH_DIGESTMD5;
      else if (strncasecmp(ptr, "BASIC", 4) == 0)
        http_auth_mechanism = AUTH_BASIC;
      else
        fprintf(stderr, "[WARNING] unknown http auth type: %s\n", ptr);

      while (*ptr != 0 && *ptr != ':')
        ptr++;

      if (*ptr != 0) {
        *ptr = 0;
        ptr += 1;
      }

      miscptr = ptr;
      break;
    case 'c': // fall through
    case 'C':
      ptr = miscptr + 2;
      while (*ptr != 0 && (*ptr != ':' || *(ptr - 1) == '\\'))
        ptr++;
      if (*ptr != 0)
        *ptr++ = 0;
      sprintf(cookieurl, "%.1000s", hydra_strrep(miscptr + 2, "\\:", ":"));
      miscptr = ptr;
      break;
    case '2':
      code_302_is_success = 1;
      char *tmp = strchr(miscptr, ':');
      if (tmp)
        miscptr = tmp + 1;
      else
        miscptr += strlen(miscptr);
      break;
    case 'g': // fall through
    case 'G':
      ptr = miscptr + 2;
      while (*ptr != 0 && (*ptr != ':' || *(ptr - 1) == '\\'))
        ptr++;
      if (*ptr != 0)
        *ptr++ = 0;
      getcookie = 0;
      miscptr = ptr;
      break;
    case 'h':
      // add a new header at the end
      ptr = miscptr + 2;
      while (*ptr != 0 && *ptr != ':')
        ptr++;
      if (*(ptr - 1) == '\\')
        *(ptr - 1) = 0;
      if (*ptr != 0) {
        *ptr = 0;
        ptr += 1;
      }
      ptr2 = ptr;
      while (*ptr2 != 0 && (*ptr2 != ':' || *(ptr2 - 1) == '\\'))
        ptr2++;
      if (*ptr2 != 0)
        *ptr2++ = 0;
      /*
       * At this point:
       *  - (optional1 + 2) contains the header's name
       *  - ptr contains the header's value
       */
      if (add_header(ptr_head, miscptr + 2, hydra_strrep(ptr, "\\:", ":"), HEADER_TYPE_USERHEADER)) {
        // Success: break the switch and go ahead
        miscptr = ptr2;
        break;
      }
      // Error: abort execution
      hydra_report(stderr, "[ERROR] Out of memory for HTTP headers (h).\n");
      return 0;
    case 'H':
      // add a new header, or replace an existing one's value
      ptr = miscptr + 2;
      while (*ptr != 0 && *ptr != ':')
        ptr++;

      if (*(ptr - 1) == '\\')
        *(ptr - 1) = 0;

      if (*ptr != 0) {
        *ptr = 0;
        ptr += 1;
      }
      ptr2 = ptr;
      while (*ptr2 != 0 && (*ptr2 != ':' || *(ptr2 - 1) == '\\'))
        ptr2++;
      if (*ptr2 != 0)
        *ptr2++ = 0;
      /*
       * At this point:
       *  - (optional1 + 2) contains the header's name
       *  - ptr contains the header's value
       */
      if (add_header(ptr_head, miscptr + 2, hydra_strrep(ptr, "\\:", ":"), HEADER_TYPE_USERHEADER_REPL)) {
        // Success: break the switch and go ahead
        miscptr = ptr2;
        break;
      }
      // Error: abort execution
      hydra_report(stderr, "[ERROR] Out of memory for HTTP headers (H).\n");
      return 0;
    default:
      hydra_report(stderr, "[ERROR] no valid optional parameter type given: %c\n", miscptr[0]);
      return 0;
    }
  }
  return 1;
}

char *prepare_http_request(char *type, char *path, char *params, char *headers) {
  uint32_t reqlen = 0;
  char *http_request = NULL;

  if (type && path && headers) {
    reqlen = strlen(path) + strlen(headers) + 20;
    if (params)
      reqlen += strlen(params);

    http_request = (char *)malloc(reqlen);
    if (http_request) {
      memset(http_request, 0, reqlen);

      // append the request verb (GET or POST)
      if (strcmp(type, "GET") == 0)
        strcat(http_request, "GET ");
      else
        strcat(http_request, "POST ");

      // append the request path
      strcat(http_request, path);

      // if GET, append the params now
      if (params && strcmp(type, "GET") == 0) {
        strcat(http_request, "?");
        strcat(http_request, params);
      }
      // append the headers
      strcat(http_request, " HTTP/1.0\r\n");
      strcat(http_request, headers);
      strcat(http_request, "\r\n");

      // if POST, append the params now
      if (params && strcmp(type, "POST") == 0)
        strcat(http_request, params);
    }
  }

  return http_request;
}

int32_t strpos(char *str, char *target) {
  char *res = strstr(str, target);

  if (res == NULL)
    return -1;
  else
    return res - str;
}

char *html_encode(char *string) {
  char *ret = string;

  if (ret == NULL)
    return NULL;

  if (strchr(ret, '%') != NULL)
    ret = hydra_strrep(ret, "%", "%25");
  if (strchr(ret, ' ') != NULL)
    ret = hydra_strrep(ret, " ", "%20");
  if (strchr(ret, '&') != NULL)
    ret = hydra_strrep(ret, "&", "%26");
  if (strchr(ret, '#') != NULL)
    ret = hydra_strrep(ret, "#", "%23");
  if (strchr(ret, '=') != NULL)
    ret = hydra_strrep(ret, "=", "%3D");
  if (strchr(ret, '+') != NULL)
    ret = hydra_strrep(ret, "+", "%2B");

  return ret;
}

/*
int32_t analyze_server_response(int32_t socket)
return 0 or 1 when the cond regex is matched
return -1 if no response from server
*/
int32_t analyze_server_response(int32_t s) {
  int32_t runs = 0;

  redirected_flag = 0;
  auth_flag = 0;
  while ((buf = hydra_receive_line(s)) != NULL) {
    runs++;
    // check for http redirection
    if (strstr(buf, "HTTP/1.1 3") != NULL || strstr(buf, "HTTP/1.0 3") != NULL || strstr(buf, "Status: 3") != NULL) {
      redirected_flag = 1;
    } else if (strstr(buf, "HTTP/1.1 401") != NULL || strstr(buf, "HTTP/1.0 401") != NULL) {
      auth_flag = 1;
    } else if ((strstr(buf, "HTTP/1.1 403") != NULL) || (strstr(buf, "HTTP/1.1 404") != NULL) || (strstr(buf, "HTTP/1.0 403") != NULL) || (strstr(buf, "HTTP/1.0 404") != NULL)) {
      return -1;
    }

    if (hydra_strcasestr(buf, "Location: ") != NULL) {
      char *startloc, *endloc;
      char str[2048];

      startloc = hydra_strcasestr(buf, "Location: ") + strlen("Location: ");
      strncpy(str, startloc, sizeof(str) - 1);
      str[sizeof(str) - 1] = 0;
      endloc = strchr(str, '\n');
      if (endloc != NULL)
        *endloc = 0;
      endloc = strchr(str, '\r');
      if (endloc != NULL)
        *endloc = 0;
      strcpy(redirected_url_buff, str);
    }
    // there can be multiple cookies
    if (hydra_strcasestr(buf, "Set-Cookie: ") != NULL) {
      char *cookiebuf = buf;

      do {
        char *startcookie, *endcookie1, *endcookie2;
        char str[1024], tmpcookie[4096] = "", tmpname[128] = "", *ptr, *ptr2;

        memset(str, 0, sizeof(str));
        startcookie = hydra_strcasestr(cookiebuf, "Set-Cookie: ") + strlen("Set-Cookie: ");
        strncpy(str, startcookie, sizeof(str) - 1);
        str[sizeof(str) - 1] = 0;
        endcookie1 = strchr(str, '\n');
        endcookie2 = strchr(str, ';');
        // terminate string after cookie data
        if (endcookie1 != NULL && ((endcookie1 < endcookie2) || (endcookie2 == NULL))) {
          if (*(endcookie1 - 1) == '\r')
            endcookie1--;
          *endcookie1 = 0;
        } else if (endcookie2 != NULL)
          *endcookie2 = 0;
        // is the cookie already there? if yes, remove it!
        if (strchr(startcookie, '=') != NULL && (ptr = strchr(startcookie, '=')) - startcookie + 1 <= sizeof(tmpname)) {
          strncpy(tmpname, startcookie, sizeof(tmpname) - 2);
          tmpname[sizeof(tmpname) - 2] = 0;
          ptr = strchr(tmpname, '=');
          *(++ptr) = 0;
          // is the cookie already in the cookiejar? (so, does it have to be
          // replaced?)
          if ((ptr = hydra_strcasestr(cookie, tmpname)) != NULL) {
            // yes it is.
            // if the cookie is not in the beginning of the cookiejar, copy the
            // ones before
            if (ptr != cookie && *(ptr - 1) == ' ') {
              strncpy(tmpcookie, cookie, ptr - cookie - 2);
              tmpcookie[ptr - cookie - 2] = 0;
            }
            ptr += strlen(tmpname);
            // if there are any cookies after this one in the cookiejar, copy
            // them over
            if ((ptr2 = strstr(ptr, "; ")) != NULL) {
              ptr2 += 2;
              strncat(tmpcookie, ptr2, sizeof(tmpcookie) - strlen(tmpcookie) - 1);
            }
            if (debug)
              printf("[DEBUG] removing cookie %s in jar\n before: %s\n after:  "
                     "%s\n",
                     tmpname, cookie, tmpcookie);
            strcpy(cookie, tmpcookie);
          }
        }
        ptr = strchr(str, '=');
        // only copy the cookie if it has a value (otherwise the server wants to
        // delete the cookie)
        if (ptr != NULL && *(ptr + 1) != ';' && *(ptr + 1) != 0 && *(ptr + 1) != '\n' && *(ptr + 1) != '\r') {
          if (strlen(cookie) > 0)
            strncat(cookie, "; ", sizeof(cookie) - strlen(cookie) - 1);
          strncat(cookie, str, sizeof(cookie) - strlen(cookie) - 1);
        }
        cookiebuf = startcookie;
      } while (hydra_strcasestr(cookiebuf, "Set-Cookie: ") != NULL);
    }
#ifdef HAVE_PCRE
    if (hydra_string_match(buf, cond) == 1) {
#else
    if (strstr(buf, cond) != NULL) {
#endif
      free(buf);
      //      printf("DEBUG: STRING %s FOUND!!:\n%s\n", cond, buf);
      return 1;
    }
    //    else printf("DEBUG: STRING %s NOT FOUND:\n%s\n", cond, buf);
    free(buf);
  }
  if (runs == 0) {
    if (debug)
      hydra_report(stderr, "DEBUG: no response from server\n");
    return -1;
  }
  return 0;
}

void hydra_reconnect(int32_t s, char *ip, int32_t port, unsigned char options, char *hostname) {
  if (s >= 0)
    s = hydra_disconnect(s);
  if ((options & OPTION_SSL) == 0) {
    s = hydra_connect_tcp(ip, port);
  } else {
    s = hydra_connect_ssl(ip, port, hostname);
  }
}

int32_t start_http_form(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp, char *hostname, char *type, ptr_header_node ptr_head, ptr_cookie_node ptr_cookie) {
  char *empty = "";
  char *login, *pass, clogin[256], cpass[256], b64login[345], b64pass[345];
  char header[8096], *upd3variables;
  char *cookie_header = NULL;
  char *http_request = NULL;
  int32_t found = !success_cond, i, j;
  char content_length[MAX_CONTENT_LENGTH], proxy_string[MAX_PROXY_LENGTH];

  memset(header, 0, sizeof(header));
  cookie[0] = 0; // reset cookies from potential previous attempt

  if (use_proxy > 0 && proxy_count > 0)
    selected_proxy = random() % proxy_count;

  // Take the next login/pass pair
  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;
  strcpy(b64login, login);
  hydra_tobase64((unsigned char *)b64login, strlen(b64login), sizeof(b64login));
  strcpy(b64pass, pass);
  hydra_tobase64((unsigned char *)b64pass, strlen(b64pass), sizeof(b64pass));
  strncpy(clogin, html_encode(login), sizeof(clogin) - 1);
  clogin[sizeof(clogin) - 1] = 0;
  strncpy(cpass, html_encode(pass), sizeof(cpass) - 1);
  cpass[sizeof(cpass) - 1] = 0;
  upd3variables = hydra_strrep(variables, "^USER^", clogin);
  upd3variables = hydra_strrep(upd3variables, "^PASS^", cpass);
  upd3variables = hydra_strrep(upd3variables, "^USER64^", b64login);
  upd3variables = hydra_strrep(upd3variables, "^PASS64^", b64pass);

  // Replace the user/pass placeholders in the user-supplied headers
  hdrrep(&ptr_head, "^USER^", clogin);
  hdrrep(&ptr_head, "^PASS^", cpass);
  hdrrep(&ptr_head, "^USER64^", b64login);
  hdrrep(&ptr_head, "^PASS64^", b64pass);

  /* again: no snprintf to be portable. don't worry, buffer can't overflow */
  if (use_proxy == 1 && proxy_authentication[selected_proxy] != NULL) {
    if (getcookie) {
      memset(proxy_string, 0, sizeof(proxy_string));
      snprintf(proxy_string, MAX_PROXY_LENGTH - 1, "http://%s:%d%.600s", webtarget, webport, cookieurl);
      if (http_request != NULL)
        free(http_request);
      http_request = prepare_http_request("GET", proxy_string, NULL, cookie_request);
      if (hydra_send(s, http_request, strlen(http_request), 0) < 0)
        return 1;
      i = analyze_server_response(s); // ignore result
      if (strlen(cookie) > 0)
        process_cookies(&ptr_cookie, cookie);
      hydra_reconnect(s, ip, port, options, hostname);
    }
    // now prepare for the "real" request
    if (strcmp(type, "POST") == 0) {
      memset(proxy_string, 0, sizeof(proxy_string));
      snprintf(proxy_string, MAX_PROXY_LENGTH - 1, "http://%s:%d%.600s", webtarget, webport, url);
      snprintf(content_length, MAX_CONTENT_LENGTH - 1, "%d", (int32_t)strlen(upd3variables));
      if (header_exists(&ptr_head, "Content-Length", HEADER_TYPE_DEFAULT))
        hdrrepv(&ptr_head, "Content-Length", content_length);
      else
        add_header(&ptr_head, "Content-Length", content_length, HEADER_TYPE_DEFAULT);
      if (!header_exists(&ptr_head, "Content-Type", HEADER_TYPE_DEFAULT))
        add_header(&ptr_head, "Content-Type", "application/x-www-form-urlencoded", HEADER_TYPE_DEFAULT);
      if (cookie_header != NULL)
        free(cookie_header);
      cookie_header = stringify_cookies(ptr_cookie);
      if (!header_exists(&ptr_head, "Cookie", HEADER_TYPE_DEFAULT))
        add_header(&ptr_head, "Cookie", cookie_header, HEADER_TYPE_DEFAULT);
      else
        hdrrepv(&ptr_head, "Cookie", cookie_header);
      if (normal_request != NULL)
        free(normal_request);
      normal_request = stringify_headers(&ptr_head);
      if (http_request != NULL)
        free(http_request);
      http_request = prepare_http_request("POST", proxy_string, upd3variables, normal_request);
      if (hydra_send(s, http_request, strlen(http_request), 0) < 0)
        return 1;
    } else {
      if (header_exists(&ptr_head, "Content-Length", HEADER_TYPE_DEFAULT))
        hdrrepv(&ptr_head, "Content-Length", "0");
      if (cookie_header != NULL)
        free(cookie_header);
      cookie_header = stringify_cookies(ptr_cookie);
      if (!header_exists(&ptr_head, "Cookie", HEADER_TYPE_DEFAULT))
        add_header(&ptr_head, "Cookie", cookie_header, HEADER_TYPE_DEFAULT);
      else
        hdrrepv(&ptr_head, "Cookie", cookie_header);
      if (normal_request != NULL)
        free(normal_request);
      normal_request = stringify_headers(&ptr_head);
      if (http_request != NULL)
        free(http_request);
      http_request = prepare_http_request("GET", proxy_string, upd3variables, normal_request);
      if (hydra_send(s, http_request, strlen(http_request), 0) < 0)
        return 1;
    }
  } else {
    if (use_proxy == 1) {
      // proxy without authentication
      if (getcookie) {
        // doing a GET to get cookies
        memset(proxy_string, 0, sizeof(proxy_string));
        snprintf(proxy_string, MAX_PROXY_LENGTH - 1, "http://%s:%d%.600s", webtarget, webport, cookieurl);
        if (http_request != NULL)
          free(http_request);
        http_request = prepare_http_request("GET", proxy_string, NULL, cookie_request);
        if (hydra_send(s, http_request, strlen(http_request), 0) < 0)
          return 1;
        i = analyze_server_response(s); // ignore result
        if (strlen(cookie) > 0)
          process_cookies(&ptr_cookie, cookie);
        hydra_reconnect(s, ip, port, options, hostname);
      }
      // now prepare for the "real" request
      if (strcmp(type, "POST") == 0) {
        memset(proxy_string, 0, sizeof(proxy_string));
        snprintf(proxy_string, MAX_PROXY_LENGTH - 1, "http://%s:%d%.600s", webtarget, webport, url);
        snprintf(content_length, MAX_CONTENT_LENGTH - 1, "%d", (int32_t)strlen(upd3variables));
        if (header_exists(&ptr_head, "Content-Length", HEADER_TYPE_DEFAULT))
          hdrrepv(&ptr_head, "Content-Length", content_length);
        else
          add_header(&ptr_head, "Content-Length", content_length, HEADER_TYPE_DEFAULT);
        if (!header_exists(&ptr_head, "Content-Type", HEADER_TYPE_DEFAULT))
          add_header(&ptr_head, "Content-Type", "application/x-www-form-urlencoded", HEADER_TYPE_DEFAULT);
        if (cookie_header != NULL)
          free(cookie_header);
        cookie_header = stringify_cookies(ptr_cookie);
        if (!header_exists(&ptr_head, "Cookie", HEADER_TYPE_DEFAULT))
          add_header(&ptr_head, "Cookie", cookie_header, HEADER_TYPE_DEFAULT);
        else
          hdrrepv(&ptr_head, "Cookie", cookie_header);
        if (normal_request != NULL)
          free(normal_request);
        normal_request = stringify_headers(&ptr_head);
        if (http_request != NULL)
          free(http_request);
        http_request = prepare_http_request("POST", proxy_string, upd3variables, normal_request);
        if (hydra_send(s, http_request, strlen(http_request), 0) < 0)
          return 1;
      } else {
        if (header_exists(&ptr_head, "Content-Length", HEADER_TYPE_DEFAULT))
          hdrrepv(&ptr_head, "Content-Length", "0");
        if (cookie_header != NULL)
          free(cookie_header);
        cookie_header = stringify_cookies(ptr_cookie);
        if (!header_exists(&ptr_head, "Cookie", HEADER_TYPE_DEFAULT))
          add_header(&ptr_head, "Cookie", cookie_header, HEADER_TYPE_DEFAULT);
        else
          hdrrepv(&ptr_head, "Cookie", cookie_header);
        if (normal_request != NULL)
          free(normal_request);
        normal_request = stringify_headers(&ptr_head);
        if (http_request != NULL)
          free(http_request);
        http_request = prepare_http_request("GET", proxy_string, upd3variables, normal_request);
        if (hydra_send(s, http_request, strlen(http_request), 0) < 0)
          return 1;
      }
    } else {
      // direct web server, no proxy
      normal_request = NULL;
      if (getcookie) {
        // doing a GET to save cookies
        if (http_request != NULL)
          free(http_request);
        http_request = prepare_http_request("GET", cookieurl, NULL, cookie_request);
        if (hydra_send(s, http_request, strlen(http_request), 0) < 0)
          return 1;
        i = analyze_server_response(s); // ignore result
        if (strlen(cookie) > 0) {
          // printf("[DEBUG] Got cookie: %s\n", cookie);
          process_cookies(&ptr_cookie, cookie);
          if (normal_request != NULL)
            free(normal_request);
          normal_request = stringify_headers(&ptr_head);
        }
        hydra_reconnect(s, ip, port, options, hostname);
      }
      // now prepare for the "real" request
      if (strcmp(type, "POST") == 0) {
        snprintf(content_length, MAX_CONTENT_LENGTH - 1, "%d", (int32_t)strlen(upd3variables));
        if (header_exists(&ptr_head, "Content-Length", HEADER_TYPE_DEFAULT))
          hdrrepv(&ptr_head, "Content-Length", content_length);
        else
          add_header(&ptr_head, "Content-Length", content_length, HEADER_TYPE_DEFAULT);
        if (!header_exists(&ptr_head, "Content-Type", HEADER_TYPE_DEFAULT))
          add_header(&ptr_head, "Content-Type", "application/x-www-form-urlencoded", HEADER_TYPE_DEFAULT);
        if (cookie_header != NULL)
          free(cookie_header);
        cookie_header = stringify_cookies(ptr_cookie);
        if (!header_exists(&ptr_head, "Cookie", HEADER_TYPE_DEFAULT))
          add_header(&ptr_head, "Cookie", cookie_header, HEADER_TYPE_DEFAULT);
        else
          hdrrepv(&ptr_head, "Cookie", cookie_header);
        if (normal_request != NULL)
          free(normal_request);
        normal_request = stringify_headers(&ptr_head);
        if (http_request != NULL)
          free(http_request);
        http_request = prepare_http_request("POST", url, upd3variables, normal_request);
        if (hydra_send(s, http_request, strlen(http_request), 0) < 0)
          return 1;
      } else {
        if (header_exists(&ptr_head, "Content-Length", HEADER_TYPE_DEFAULT))
          hdrrepv(&ptr_head, "Content-Length", "0");
        if (cookie_header != NULL)
          free(cookie_header);
        cookie_header = stringify_cookies(ptr_cookie);
        if (!header_exists(&ptr_head, "Cookie", HEADER_TYPE_DEFAULT))
          add_header(&ptr_head, "Cookie", cookie_header, HEADER_TYPE_DEFAULT);
        else
          hdrrepv(&ptr_head, "Cookie", cookie_header);
        if (normal_request != NULL)
          free(normal_request);
        normal_request = stringify_headers(&ptr_head);
        if (http_request != NULL)
          free(http_request);
        http_request = prepare_http_request("GET", url, upd3variables, normal_request);
        if (hydra_send(s, http_request, strlen(http_request), 0) < 0)
          return 1;
      }
    }
  }

  if (debug)
    hydra_report_debug(stdout, "HTTP request sent:\n%s\n", http_request);

  found = analyze_server_response(s);

  if (redirected_flag && code_302_is_success) {
    found = success_cond;
  }

  if (auth_flag) { // we received a 401 error - user is using wrong module
    hydra_report(stderr,
                 "[ERROR] the target is using HTTP auth, not a web form, received HTTP "
                 "error code 401. Use module \"http%s-get\" instead.\n",
                 (options & OPTION_SSL) > 0 ? "s" : "");
    return 2;
  }

  if (strlen(cookie) > 0)
    process_cookies(&ptr_cookie, cookie);

  // if page was redirected, follow the location header
  redirected_cpt = MAX_REDIRECT;
  if (debug)
    printf("[DEBUG] attempt result: found %d, redirect %d, location: %s\n", found, redirected_flag, redirected_url_buff);

  while (found == 0 && redirected_flag && !code_302_is_success && (redirected_url_buff[0] != 0) && (redirected_cpt > 0)) {
    // we have to split the location
    char *startloc, *endloc;
    char str[2048], str2[2048], str3[2048], str4[2048];

    redirected_cpt--;
    redirected_flag = 0;
    // check if the redirect page contains the fail/success condition
#ifdef HAVE_PCRE
    if (hydra_string_match(redirected_url_buff, cond) == 1) {
#else
    if (strstr(redirected_url_buff, cond) != NULL) {
#endif
      found = success_cond;
    } else {
      // location could be either absolute http(s):// or / something
      // or relative
      startloc = strstr(redirected_url_buff, "://");
      if (startloc != NULL) {
        startloc += strlen("://");

        if ((endloc = strchr(startloc, '\r')) != NULL) {
          *endloc = 0;
        }
        if ((endloc = strchr(startloc, '\n')) != NULL) {
          *endloc = 0;
        }
        strncpy(str, startloc, sizeof(str) - 1);
        str[sizeof(str) - 1] = 0;

        endloc = strchr(str, '/');
        if (endloc != NULL) {
          strncpy(str2, str, endloc - str);
          str2[endloc - str] = 0;
        } else {
          strcpy(str2, str);
        }

        if (strlen(str) - strlen(str2) == 0) {
          strcpy(str3, "/");
        } else {
          strncpy(str3, str + strlen(str2), strlen(str) - strlen(str2));
          str3[strlen(str) - strlen(str2)] = 0;
        }
      } else {
        strncpy(str2, webtarget, sizeof(str2) - 1);
        str2[sizeof(str2) - 1] = 0;
        if (redirected_url_buff[0] != '/') {
          // it's a relative path, so we have to concatenate it
          // with the path from the first url given
          char *urlpath;
          char urlpath_extracted[2048];

          memset(urlpath_extracted, 0, sizeof(urlpath_extracted));

          urlpath = strrchr(url, '/');
          if (urlpath != NULL) {
            strncpy(urlpath_extracted, url, urlpath - url);
            sprintf(str3, "%.1000s/%.1000s", urlpath_extracted, redirected_url_buff);
          } else {
            sprintf(str3, "%.1000s/%.1000s", url, redirected_url_buff);
          }
        } else {
          strncpy(str3, redirected_url_buff, sizeof(str3) - 1);
          str3[sizeof(str3) - 1] = 0;
        }
        if (debug)
          hydra_report(stderr, "[DEBUG] host=%s redirect=%s origin=%s\n", str2, str3, url);
      }
      if (str3[0] != '/') {
        j = strlen(str3);
        str3[j + 1] = 0;
        for (i = j; i > 0; i--)
          str3[i] = str3[i - 1];
        str3[0] = '/';
      }

      if (strrchr(str2, ':') == NULL && (port != 80 || port != 443)) {
        sprintf(str4, "%.2000s:%d", str2, port);
        strcpy(str2, str4);
      }

      if (verbose)
        hydra_report(stderr, "[VERBOSE] Page redirected to http[s]://%s%s\n", str2, str3);

      if (header_exists(&ptr_head, "Content-Length", HEADER_TYPE_DEFAULT))
        hdrrepv(&ptr_head, "Content-Length", "0");

      // re-use the above code to set cookies
      if (cookie_header != NULL)
        free(cookie_header);
      cookie_header = stringify_cookies(ptr_cookie);
      if (!header_exists(&ptr_head, "Cookie", HEADER_TYPE_DEFAULT))
        add_header(&ptr_head, "Cookie", cookie_header, HEADER_TYPE_DEFAULT);
      else
        hdrrepv(&ptr_head, "Cookie", cookie_header);

      // re-use the code above to check for proxy use
      if (use_proxy == 1 && proxy_authentication[selected_proxy] != NULL) {
        // proxy with authentication
        hdrrepv(&ptr_head, "Host", str2);
        memset(proxy_string, 0, sizeof(proxy_string));
        snprintf(proxy_string, MAX_PROXY_LENGTH - 1, "http://%s:%d%.600s", webtarget, webport, str3);
        if (normal_request != NULL)
          free(normal_request);
        normal_request = stringify_headers(&ptr_head);
        if (http_request != NULL)
          free(http_request);
        http_request = prepare_http_request("GET", proxy_string, NULL, normal_request);
      } else {
        if (use_proxy == 1) {
          // proxy without authentication
          hdrrepv(&ptr_head, "Host", str2);
          memset(proxy_string, 0, sizeof(proxy_string));
          snprintf(proxy_string, MAX_PROXY_LENGTH - 1, "http://%s:%d%.600s", webtarget, webport, str3);
          if (normal_request != NULL)
            free(normal_request);
          normal_request = stringify_headers(&ptr_head);
          if (http_request != NULL)
            free(http_request);
          http_request = prepare_http_request("GET", proxy_string, NULL, normal_request);
        } else {
          // direct web server, no proxy
          hdrrepv(&ptr_head, "Host", str2);
          if (normal_request != NULL)
            free(normal_request);
          normal_request = stringify_headers(&ptr_head);
          if (http_request != NULL)
            free(http_request);
          http_request = prepare_http_request("GET", str3, NULL, normal_request);
        }
      }

      hydra_reconnect(s, ip, port, options, hostname);

      if (hydra_send(s, http_request, strlen(http_request), 0) < 0)
        return 1;

      found = analyze_server_response(s);
      if (strlen(cookie) > 0)
        process_cookies(&ptr_cookie, cookie);
    }
  }

  // if the last status is still 3xx, set it as a false
  if (found != -1 && found == success_cond && ((redirected_flag && code_302_is_success) || redirected_flag == 0 || success_cond == 1) && redirected_cpt >= 0) {
    hydra_report_found_host(port, ip, "www-form", fp);
    hydra_completed_pair_found();
  } else {
    hydra_completed_pair();
  }

  return 1;
}

void service_http_form(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname, char *type, ptr_header_node *ptr_head, ptr_cookie_node *ptr_cookie) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_HTTP, mysslport = PORT_HTTP_SSL;

  // register our socket descriptor
  hydra_register_socket(sp);

  /*
   * Iterate through the runs. Possible values are the following:
   *    - 1 -> Open connection to remote server.
   *    - 2 -> Run password attempts.
   *    - 3 -> Disconnect and end with success.
   *    - 4 -> Disconnect and end with error.
   */

  while (1) {
    if (run == 2) {
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0) {
        hydra_child_exit(1);
      }
    }
    switch (run) {
    case 1: /* connect and service init function */
    {
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      if ((options & OPTION_SSL) == 0) {
        if (port != 0)
          myport = port;
        sock = hydra_connect_tcp(ip, myport);
        port = myport;
      } else {
        if (port != 0)
          mysslport = port;
        sock = hydra_connect_ssl(ip, mysslport, hostname);
        port = mysslport;
      }
      if (sock < 0) {
        hydra_report(stderr, "[ERROR] Child with pid %d terminating, cannot connect\n", (int32_t)getpid());
        hydra_child_exit(1);
      }
      next_run = 2;
      break;
    }
    case 2: /* run the cracking function */
      next_run = start_http_form(sock, ip, port, options, miscptr, fp, hostname, type, *ptr_head, *ptr_cookie);
      break;
    case 3: /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
      break;
    case 4: /* silent error exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(1);
      break;
    default:
      hydra_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(0);
    }
    run = next_run;
  }
}

void service_http_get_form(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  ptr_cookie_node ptr_cookie = NULL;
  ptr_header_node ptr_head = initialize(ip, options, miscptr);

  if (ptr_head)
    service_http_form(ip, sp, options, miscptr, fp, port, hostname, "GET", &ptr_head, &ptr_cookie);
  else {
    hydra_report(stderr, "[ERROR] Could not launch head. Error while initializing.\n");
    hydra_child_exit(2);
  }
}

void service_http_post_form(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  ptr_cookie_node ptr_cookie = NULL;
  ptr_header_node ptr_head = initialize(ip, options, miscptr);

  if (ptr_head)
    service_http_form(ip, sp, options, miscptr, fp, port, hostname, "POST", &ptr_head, &ptr_cookie);
  else {
    hydra_report(stderr, "[ERROR] Could not launch head. Error while initializing.\n");
    hydra_child_exit(2);
  }
}

int32_t service_http_form_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  // called before the childrens are forked off, so this is the function
  // which should be filled if initial connections and service setup has to be
  // performed once only.
  //
  // fill if needed.
  //
  // return codes:
  //   0 all OK
  //   -1  error, hydra will exit, so print a good error message here

  if (initialize(ip, options, miscptr) == NULL)
    return 1;

  return 0;
}

ptr_header_node initialize(char *ip, unsigned char options, char *miscptr) {
  ptr_header_node ptr_head = NULL;
  char *ptr, *ptr2, *proxy_string;
#ifdef AF_INET6
  unsigned char addr6[sizeof(struct in6_addr)];
#endif

  if (use_proxy > 0 && proxy_count > 0)
    selected_proxy = random() % proxy_count;

  if (webtarget) {
    free(webtarget);
    webtarget = NULL;
  }

  if (cmdlinetarget != NULL)
    webtarget = cmdlinetarget;
  else
    webtarget = hydra_address2string(ip);
  if (port != 0)
    webport = port;
  else if ((options & OPTION_SSL) == 0)
    webport = PORT_HTTP;
  else
    webport = PORT_HTTP_SSL;

  /* normalise the webtarget for ipv6/port number */
  ptr = malloc(strlen(webtarget) + 1 /* null */ + 6 /* :65535  */
#ifdef AF_INET6
               + 2 /* [] */
#endif
  );
#ifdef AF_INET6
  /* let libc decide if target is an ipv6 address */
  if (inet_pton(AF_INET6, webtarget, addr6)) {
    ptr2 = ptr + sprintf(ptr, "[%s]", webtarget);
  } else {
#endif
    ptr2 = ptr + sprintf(ptr, "%s", webtarget);
#ifdef AF_INET6
  }
#endif
  if (options & OPTION_SSL && webport != PORT_HTTP_SSL || !(options & OPTION_SSL) && webport != PORT_HTTP) {
    sprintf(ptr2, ":%d", webport);
  }
  webtarget = ptr;
  ptr = ptr2 = NULL;

  sprintf(bufferurl, "%.6096s", miscptr);
  ptr = url = bufferurl;

  while (*ptr != 0 && (*ptr != ':' || *(ptr - 1) == '\\'))
    ptr++;
  if (*ptr != 0)
    *ptr++ = 0;
  variables = ptr;

  while (*ptr != 0 && (*ptr != ':' || *(ptr - 1) == '\\'))
    ptr++;
  if (*ptr != 0)
    *ptr++ = 0;

  optional1 = cond = ptr;

  ptr2 = ptr + strlen(ptr);

  while (ptr2 > ptr && (*ptr2 != ':' || *(ptr2 - 1) == '\\'))
    ptr2--;

  if (*ptr2 == ':') {
    *ptr2++ = 0;
    cond = ptr2;
  }

  if (optional1 == cond)
    optional1 = NULL;

  if (strstr(url, "\\:") != NULL) {
    if ((ptr = malloc(strlen(url) + 1)) != NULL) {
      strcpy(ptr, hydra_strrep(url, "\\:", ":"));
      url = ptr;
    }
  }
  if (strstr(variables, "\\:") != NULL) {
    if ((ptr = malloc(strlen(variables) + 1)) != NULL) {
      strcpy(ptr, hydra_strrep(variables, "\\:", ":"));
      variables = ptr;
    }
  }
  if (strstr(cond, "\\:") != NULL) {
    if ((ptr = malloc(strlen(cond) + 1)) != NULL) {
      strcpy(ptr, hydra_strrep(cond, "\\:", ":"));
      cond = ptr;
    }
  }

  // printf("ptr: %s  ptr2: %s  cond: %s  url: %s  variables: %s  optional1: %s\n", ptr, ptr2, cond, url, variables, optional1 == NULL ? "null" : optional1);

  if (url == NULL || variables == NULL || cond == NULL /*|| optional1 == NULL */)
    hydra_child_exit(2);

  if (*cond == 0) {
    fprintf(stderr, "[ERROR] invalid number of parameters in module option\n");
    return NULL;
  }

  sprintf(cookieurl, "%.1000s", url);

  // conditions now have to contain F or S to set the fail or success condition
  if (strpos(cond, "F=") == 0) {
    success_cond = 0;
    cond += 2;
  } else if (*cond != 0 && (strpos(cond, "S=") == 0)) {
    success_cond = 1;
    cond += 2;
  } else {
    // by default condition is a fail
    success_cond = 0;
  }

  // printf("miscptr: %s, url=%s, variables=%s, ptr=%s, optional1: %s, cond: %s (%d)\n", miscptr, url, variables, ptr, optional1, cond, success_cond);

  /*
   * Parse the user-supplied options.
   * Beware of the backslashes (\)!
   */
  if (!parse_options(optional1, &ptr_head))
    return NULL;

  /* again: no snprintf to be portable. don't worry, buffer can't overflow */
  if (use_proxy == 1 && proxy_authentication[selected_proxy] != NULL) {
    // proxy with authentication
    add_header(&ptr_head, "Host", webtarget, HEADER_TYPE_DEFAULT);
    add_header(&ptr_head, "User-Agent", "Mozilla 5.0 (Hydra Proxy Auth)", HEADER_TYPE_DEFAULT);
    proxy_string = (char *)malloc(strlen(proxy_authentication[selected_proxy]) + 10);
    if (proxy_string) {
      strcpy(proxy_string, "Basic ");
      strcat(proxy_string, proxy_authentication[selected_proxy]);
      add_header(&ptr_head, "Proxy-Authorization", proxy_string, HEADER_TYPE_DEFAULT);
    } else {
      hydra_report(stderr, "Out of memory for \"Proxy-Authorization\" header.\n");
      return NULL;
    }
    if (getcookie) {
      // doing a GET to save cookies
      if (cookie_request != NULL)
        free(cookie_request);
      cookie_request = stringify_headers(&ptr_head);
    }
    if (normal_request != NULL)
      free(normal_request);
    normal_request = stringify_headers(&ptr_head);
  } else {
    if (use_proxy == 1) {
      // proxy without authentication
      add_header(&ptr_head, "Host", webtarget, HEADER_TYPE_DEFAULT);
      add_header(&ptr_head, "User-Agent", "Mozilla/5.0 (Hydra Proxy)", HEADER_TYPE_DEFAULT);
      if (getcookie) {
        // doing a GET to get cookies
        if (cookie_request != NULL)
          free(cookie_request);
        cookie_request = stringify_headers(&ptr_head);
      }
      if (normal_request != NULL)
        free(normal_request);
      normal_request = stringify_headers(&ptr_head);
    } else {
      // direct web server, no proxy
      add_header(&ptr_head, "Host", webtarget, HEADER_TYPE_DEFAULT);
      add_header(&ptr_head, "User-Agent", "Mozilla/5.0 (Hydra)", HEADER_TYPE_DEFAULT);

      if (getcookie) {
        // doing a GET to save cookies
        if (cookie_request != NULL)
          free(cookie_request);
        cookie_request = stringify_headers(&ptr_head);
      }

      if (normal_request != NULL)
        free(normal_request);
      normal_request = stringify_headers(&ptr_head);
    }
  }

  return ptr_head;
}

void usage_http_form(const char *service) {
  printf("Module %s requires the page and the parameters for the web form.\n\n"
         "By default this module is configured to follow a maximum of 5 "
         "redirections in\n"
         "a row. It always gathers a new cookie from the same URL without "
         "variables\n"
         "The parameters requires three \":\" separated values, plus optional "
         "values.\n"
         "(Note: if you need a colon in the option string as value, escape it "
         "with \"\\:\", but do not escape a \"\\\" with \"\\\\\".)\n"
         "\nSyntax: <url>:<form parameters>[:<optional>[:<optional>]:<condition string>\n"
         "\nFirst is the page on the server to GET or POST to (URL), e.g. \"/login\".\n"
         "Second is the POST/GET variables (taken from either the browser, proxy, etc.)\n"
         " without the initial '?' character and the usernames and passwords being\n"
         " replaced with \"^USER^\" (\"^USER64^\" for base64 encodings) and \"^PASS^\"\n"
         " (\"^PASS64^\" for base64 encodings).\n"
         "Third are optional parameters (see below)\n"
         "Last is the string that it checks for an *invalid* login (by default).\n"
         " Invalid condition login check can be preceded by \"F=\", successful condition\n"
         " login check must be preceded by \"S=\".\n"
         " This is where most people get it wrong! You have to check the webapp what a\n"
         " failed string looks like and put it in this parameter! Add the -d switch to see\n"
         " the sent/received data!\n"
         " Note that using invalid login condition checks can result in false positives!\n"
         "\nThe following parameters are optional and are put between the form parameters\n"
         "  and the condition string; seperate them too with colons:\n"
         " 2=                  302 page forward return codes identify a successful attempt\n"
         " (c|C)=/page/uri     to define a different page to gather initial "
         "cookies from\n"
         " (g|G)=              skip pre-requests - only use this when no pre-cookies are required\n"
         " (h|H)=My-Hdr\\: foo   to send a user defined HTTP header with each "
         "request\n"
         "                 ^USER[64]^ and ^PASS[64]^ can also be put into these "
         "headers!\n"
         "                 Note: 'h' will add the user-defined header at the end\n"
         "                 regardless it's already being sent by Hydra or not.\n"
         "                 'H' will replace the value of that header if it "
         "exists, by the\n"
         "                 one supplied by the user, or add the header at the "
         "end\n"
         "\nNote that if you are going to put colons (:) in your headers you should escape\n"
         "them with a backslash (\\). All colons that are not option separators should be\n"
         "escaped (see the examples above and below).\n"
         "You can specify a header without escaping the colons, but that way you will not\n"
         "be able to put colons in the header value itself, as they will be interpreted by\n"
         "hydra as option separators.\n"
         "\nExamples:\n"
         " \"/login.php:user=^USER^&pass=^PASS^:incorrect\"\n"
         " \"/"
         "login.php:user=^USER64^&pass=^PASS64^&colon=colon\\:escape:S=result="
         "success\"\n"
         " \"/login.php:user=^USER^&pass=^PASS^&mid=123:authlog=.*failed\"\n"
         " \"/:user=^USER&pass=^PASS^:failed:H=Authorization\\: Basic "
         "dT1w:H=Cookie\\: sessid=aaaa:h=X-User\\: ^USER^:H=User-Agent\\: wget\"\n"
         " \"/exchweb/bin/auth/"
         "owaauth.dll:destination=http%%3A%%2F%%2F<target>%%2Fexchange&flags=0&"
         "username=<domain>%%5C^USER^&password=^PASS^&SubmitCreds=x&trusted=0:"
         "reason=:C=/exchweb\"\n",
         service);
}
