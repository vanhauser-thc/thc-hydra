#include "hydra-mod.h"
#include "hydra-telnet.h"
#include <ctype.h>

char *telcmds[] = {
  "EOF", "SUSP", "ABORT", "EOR",
  "SE", "NOP", "DMARK", "BRK", "IP", "AO", "AYT", "EC",
  "EL", "GA", "SB", "WILL", "WONT", "DO", "DONT", "IAC", 0,
};

extern const unsigned char HYDRA_EXIT[5];
char *buf;
int32_t no_line_mode;

/* One owner for unread prompts and negotiation state on the live socket. */
typedef struct {
  char *pending_prompt;
  unsigned char iac_state;
  unsigned char iac_command;
  int32_t line_mode_requested;
} telnet_state_t;

/* Strip negotiation bytes without discarding text in the same read. Keep
 * partial IAC commands/subnegotiations across reads, including escaped IAC. */
static char *telnet_receive_text(int32_t s, telnet_state_t *state) {
  char *text;

  while ((text = hydra_receive_line(s)) != NULL) {
    size_t input, output = 0, length = strlen(text);

    /* hydra_receive_line returns an allocated empty string on timeout. */
    if (length == 0) {
      free(text);
      return NULL;
    }
    for (input = 0; input < length; input++) {
      unsigned char byte = (unsigned char)text[input];
      switch (state->iac_state) {
      case 0: /* text */
        if (byte == IAC)
          state->iac_state = 1;
        else
          text[output++] = byte;
        break;
      case 1: /* IAC command */
        if (byte == IAC) {
          text[output++] = byte;
          state->iac_state = 0;
        } else if (byte == WILL || byte == WONT || byte == DO || byte == DONT) {
          state->iac_command = byte;
          state->iac_state = 2;
        } else {
          state->iac_state = byte == SB ? 3 : 0;
        }
        break;
      case 2: { /* option */
        char reply[3] = {(char)IAC, 0, (char)byte};
        if (!state->line_mode_requested) {
          if (hydra_send(s, "\xff\xfb\x22", 3, 0) < 0) {
            free(text);
            return NULL;
          }
          state->line_mode_requested = 1;
        }
        if ((state->iac_command == WONT || state->iac_command == DONT) && byte == 0x22)
          no_line_mode = 1;
        if (byte != 0x22) {
          reply[1] = state->iac_command == WILL || state->iac_command == WONT ? DONT : WONT;
          if (hydra_send(s, reply, sizeof(reply), 0) < 0) {
            free(text);
            return NULL;
          }
        }
        state->iac_state = 0;
        break;
      }
      case 3: /* subnegotiation */
        if (byte == IAC)
          state->iac_state = 4;
        break;
      case 4: /* IAC inside subnegotiation */
        state->iac_state = byte == SE ? 0 : 3;
        break;
      }
    }
    text[output] = 0;
    if (output != 0)
      return text;
    free(text);
  }
  return NULL;
}

/* Preserve fragmented textual prompts within a phase and consume a saved
 * re-prompt exactly once. NULL means EOF/error/timeout, never a failed login. */
static char *telnet_receive_response(int32_t s, telnet_state_t *state, char *response) {
  char *part = state->pending_prompt, *joined;
  size_t previous = response == NULL ? 0 : strlen(response), length;

  state->pending_prompt = NULL;
  if (part == NULL)
    part = telnet_receive_text(s, state);
  if (part == NULL) {
    free(response);
    return NULL;
  }
  length = strlen(part);
  if (previous + length > 65536) {
    hydra_report(stderr, "[ERROR] TELNET response exceeds 64 KiB\n");
    free(response);
    free(part);
    return NULL;
  }
  if (response == NULL)
    return part;
  joined = realloc(response, previous + length + 1);
  if (joined == NULL) {
    free(response);
    free(part);
    return NULL;
  }
  memcpy(joined + previous, part, length + 1);
  free(part);
  return joined;
}

/* Keep character-at-a-time mode on the selected transport, including SSL. */
static int32_t telnet_send_credential(int32_t s, const char *value) {
  char buffer[300];
  size_t i;

  snprintf(buffer, sizeof(buffer), "%.250s\r", value);
  if (!no_line_mode)
    return hydra_send(s, buffer, strlen(buffer) + 1, 0);
  for (i = 0; i < strlen(buffer); i++) {
    int32_t sent = buffer[i] == '\r' ? hydra_send(s, "\r\0", 2, 0) : hydra_send(s, &buffer[i], 1, 0);
    if (sent < 0)
      return -1;
    usleepn(20);
  }
  return 0;
}

/*
 * Operator-supplied success / failure substrings parsed from the optional
 * module parameter (miscptr). Either, both, or neither may be set.
 *
 *   - user_success_str : when non-NULL, the response must contain this
 *                        substring to be reported as a successful login;
 *                        replaces the structural shell-prompt heuristic.
 *   - user_failure_str : when non-NULL, the response is treated as a
 *                        failure if it contains this substring (in addition
 *                        to the built-in failure phrase list).
 *
 * Both buffers are owned by this translation unit, are lower-cased at parse
 * time, and live for the lifetime of the worker process.
 */
static char *user_success_str = NULL;
static char *user_failure_str = NULL;

/*
 * Failure-message detection.
 *
 * Patterns are deliberately specific. Earlier revisions matched single
 * generic tokens such as "wrong", "failed" or "too many" which frequently
 * appear in legitimate banners, MOTDs and help text and therefore caused
 * spurious false-negative behaviour. We only accept phrases that are
 * unambiguously associated with an authentication failure.
 *
 * The buffer is copied and lower-cased defensively even though the
 * call-sites already lower-case their input.
 */
static int is_failure(const char *buffer) {
  char temp[4096];

  if (buffer == NULL)
    return 0;

  strncpy(temp, buffer, sizeof(temp) - 1);
  temp[sizeof(temp) - 1] = 0;
  make_to_lower(temp);

  if (strstr(temp, "incorrect") != NULL ||
      strstr(temp, "invalid") != NULL ||
      strstr(temp, "denied") != NULL ||
      strstr(temp, "bad password") != NULL ||
      strstr(temp, "bad passwords") != NULL ||
      strstr(temp, "authentication failed") != NULL ||
      strstr(temp, "authentication failure") != NULL ||
      strstr(temp, "authentication error") != NULL ||
      strstr(temp, "authorization failed") != NULL ||
      strstr(temp, "login failed") != NULL ||
      strstr(temp, "login incorrect") != NULL ||
      strstr(temp, "login failure") != NULL ||
      strstr(temp, "access denied") != NULL ||
      strstr(temp, "permission denied") != NULL ||
      strstr(temp, "wrong password") != NULL ||
      strstr(temp, "wrong login") != NULL ||
      strstr(temp, "wrong username") != NULL ||
      strstr(temp, "wrong credentials") != NULL ||
      strstr(temp, "not allowed") != NULL ||
      strstr(temp, "unable to authenticate") != NULL ||
      strstr(temp, "too many attempts") != NULL ||
      strstr(temp, "too many failures") != NULL ||
      strstr(temp, "too many tries") != NULL ||
      strstr(temp, "too many logins") != NULL ||
      strstr(temp, "user was locked") != NULL ||
      strstr(temp, "account locked") != NULL ||
      strstr(temp, "account is locked") != NULL ||
      strstr(temp, "ip has been blocked") != NULL ||
      strstr(temp, "cannot log on") != NULL ||
      strstr(temp, "please retry") != NULL ||
      strstr(temp, "please try again") != NULL ||
      strstr(temp, "please try it again") != NULL ||
      strstr(temp, "username or password") != NULL ||
      strstr(temp, "user name or password") != NULL ||
      strstr(temp, "password is incorrect") != NULL ||
      strstr(temp, "bye-bye") != NULL ||
      strstr(temp, "% bad passwords") != NULL ||
      strstr(temp, "% authentication failed") != NULL ||
      strstr(temp, "% login failure") != NULL ||
      strstr(temp, "закрыт") != NULL ||
      strstr(temp, "local: authentication failure") != NULL) {
    return 1;
  }
  return 0;
}

/*
 * Failure detection that also honours the operator-supplied F= substring.
 *
 * The user-supplied pattern is checked first so an operator can override
 * (or extend) the built-in heuristics for devices whose failure banners
 * are not covered by is_failure(). The caller is expected to have lower-
 * cased the buffer; user_failure_str is lower-cased at parse time so the
 * comparison is effectively case-insensitive.
 */
static int is_failure_with_user(const char *buffer) {
  if (buffer == NULL)
    return 0;
  if (user_failure_str != NULL && *user_failure_str != 0 &&
      strstr(buffer, user_failure_str) != NULL)
    return 1;
  return is_failure(buffer);
}

/*
 * Recognise password prompts. The caller is expected to have lower-cased
 * the buffer; we use hydra_strcasestr for the multilingual stem matches
 * to stay robust against partially lowered input.
 */
static int is_password_prompt(const char *buffer) {
  if (buffer == NULL)
    return 0;
  return (hydra_strcasestr(buffer, "asswor") != NULL ||
          hydra_strcasestr(buffer, "asscode") != NULL ||
          hydra_strcasestr(buffer, "ennwort") != NULL ||
          strstr(buffer, "passwd:") != NULL ||
          strstr(buffer, "pass:") != NULL ||
          strstr(buffer, "pwd:") != NULL ||
          strstr(buffer, "pin:") != NULL ||
          strstr(buffer, "пароль") != NULL ||
          strstr(buffer, "contraseña") != NULL ||
          strstr(buffer, "enter password") != NULL ||
          strstr(buffer, "password for") != NULL);
}

/*
 * Strict login-prompt detection used after credentials have been sent.
 * Kept narrow on purpose: a post-login MOTD that contains "account:" or a
 * bare "name:" must not be interpreted as the server re-asking for a
 * username, otherwise we would discard a valid credential pair.
 */
static int is_login_prompt(const char *buffer) {
  if (buffer == NULL)
    return 0;
  return ((strstr(buffer, "ogin:") != NULL && strstr(buffer, "last login") == NULL) ||
          strstr(buffer, "sername:") != NULL);
}

/*
 * Loose login-prompt detection used only while reading the initial banner
 * to decide whether the server is in password-only mode. Matching extra
 * tokens here is safe because the worst-case outcome is that a password-
 * only server is treated as a username+password server (and we then fall
 * back to sending the username, which is the documented default).
 */
static int is_login_prompt_banner(const char *buffer) {
  if (buffer == NULL)
    return 0;
  if (is_login_prompt(buffer))
    return 1;
  return (strstr(buffer, "user:") != NULL ||
          strstr(buffer, "login:") != NULL ||
          strstr(buffer, "user id:") != NULL ||
          strstr(buffer, "userid:") != NULL ||
          strstr(buffer, "account:") != NULL ||
          strstr(buffer, "логин:") != NULL ||
          strstr(buffer, "user access verification") != NULL ||
          strstr(buffer, "user name:") != NULL ||
          strstr(buffer, "name:") != NULL);
}

/*
 * Return non-zero when the buffer ends with a recognised shell-prompt
 * character (after trimming trailing whitespace and CR/LF).
 *
 * The previous implementation looked for any of '/', '$', '#', '>' or '%'
 * anywhere inside the buffer, which produced heavy false positives:
 *   - '/' is part of nearly every path printed in a MOTD,
 *   - '$' and '#' appear in pricing, version strings, comments, etc.,
 *   - '%' appears in percentages ("100% loaded"),
 *   - '>' appears in quoted text and arrows.
 *
 * Restricting the test to the final non-whitespace byte is the minimum
 * structural cue that still recognises interactive shells (bash "$"/"#",
 * csh "%", DOS/Cisco ">") while rejecting MOTD / banner false positives.
 */
static int has_shell_prompt(const char *buffer) {
  const char *p;
  size_t len;
  char last;

  if (buffer == NULL)
    return 0;

  len = strlen(buffer);
  if (len == 0)
    return 0;

  p = buffer + len - 1;
  while (p > buffer && (*p == '\r' || *p == '\n' || *p == ' ' || *p == '\t'))
    p--;

  last = *p;
  return (last == '$' || last == '#' || last == '>' || last == '%');
}

/*
 * Decide whether a response indicates a successful login.
 *
 *   - When the operator supplied an explicit S= success string, an exact
 *     substring match is required. This is the strongest, lowest-FP mode
 *     and is the recommended way to drive the module.
 *   - Otherwise we fall back to has_shell_prompt() which only inspects
 *     the trailing non-whitespace byte of the response.
 */
static int is_success(const char *buffer) {
  if (buffer == NULL)
    return 0;
  if (user_success_str != NULL && *user_success_str != 0)
    return strstr(buffer, user_success_str) != NULL;
  return has_shell_prompt(buffer);
}

/*
 * Coarse classification of a server response after credentials have been
 * (partially or fully) submitted. Centralising this logic avoids drift
 * between the post-username and post-password phases and ensures the
 * priority order is identical in both:
 *
 *     failure phrase  >  login re-prompt  >  password prompt  >  success
 *
 * Returning TELNET_RESP_NONE means "no decision yet, keep reading".
 */
typedef enum {
  TELNET_RESP_NONE = 0,
  TELNET_RESP_SUCCESS,
  TELNET_RESP_FAILURE,
  TELNET_RESP_PASSWORD,
} telnet_resp_t;

static telnet_resp_t classify_response(const char *buffer) {
  if (buffer == NULL)
    return TELNET_RESP_NONE;
  if (is_failure_with_user(buffer))
    return TELNET_RESP_FAILURE;
  if (is_login_prompt(buffer))
    return TELNET_RESP_FAILURE;
  if (is_password_prompt(buffer))
    return TELNET_RESP_PASSWORD;
  if (is_success(buffer))
    return TELNET_RESP_SUCCESS;
  return TELNET_RESP_NONE;
}

/* A failure response may also contain the only prompt for the next pair.
 * Keep it on this socket; reconnect if no re-prompt was actually received. */
static int32_t telnet_failed_pair(telnet_state_t *state, char *response) {
  int32_t next_run = 1;

  if (is_login_prompt_banner(response) || is_password_prompt(response)) {
    state->pending_prompt = response;
    next_run = 2;
  } else {
    free(response);
  }
  hydra_completed_pair();
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;
  return next_run;
}

/*
 * Parse the optional module parameter (miscptr) into the operator-supplied
 * success / failure substrings. Accepted syntaxes:
 *
 *     <string>                 legacy: whole value used as success substring
 *     S=<success>              explicit success substring
 *     F=<failure>              explicit failure substring
 *     S=<success>:F=<failure>  both (order is irrelevant)
 *     F=<failure>:S=<success>  both (order is irrelevant)
 *
 * A literal ':' inside a value can be escaped as "\:" exactly as in the
 * http-form module, so success strings such as "Last login\:" are usable.
 *
 * The prefix detection is case-insensitive so that both "S="/"F=" and the
 * already-lower-cased "s="/"f=" produced by the call-site work the same
 * way. The function is idempotent and safe to call multiple times;
 * previous values are released first.
 */
static void telnet_parse_miscptr(char *miscptr) {
  char *work, *seg_start, *p, *unescaped;
  int has_prefix;

  if (user_success_str != NULL) {
    free(user_success_str);
    user_success_str = NULL;
  }
  if (user_failure_str != NULL) {
    free(user_failure_str);
    user_failure_str = NULL;
  }

  if (miscptr == NULL || *miscptr == 0)
    return;

  has_prefix = (strncasecmp(miscptr, "s=", 2) == 0 || strncasecmp(miscptr, "f=", 2) == 0);

  if (!has_prefix) {
    /* Legacy contract: whole value is a success substring. */
    user_success_str = strdup(miscptr);
    return;
  }

  work = strdup(miscptr);
  if (work == NULL)
    return;

  seg_start = work;
  p = work;
  while (1) {
    int at_end = (*p == 0);
    int at_sep = (*p == ':' && (p == work || *(p - 1) != '\\'));
    if (at_end || at_sep) {
      char saved = *p;
      *p = 0;
      if (strncasecmp(seg_start, "s=", 2) == 0) {
        if (user_success_str != NULL) {
          free(user_success_str);
          user_success_str = NULL;
        }
        unescaped = hydra_strrep(seg_start + 2, "\\:", ":");
        user_success_str = strdup(unescaped != NULL ? unescaped : seg_start + 2);
      } else if (strncasecmp(seg_start, "f=", 2) == 0) {
        if (user_failure_str != NULL) {
          free(user_failure_str);
          user_failure_str = NULL;
        }
        unescaped = hydra_strrep(seg_start + 2, "\\:", ":");
        user_failure_str = strdup(unescaped != NULL ? unescaped : seg_start + 2);
      } else if (*seg_start != 0) {
        hydra_report(stderr,
                     "[WARNING] telnet: ignoring unknown miscptr segment '%s' "
                     "(expected S= or F=)\n",
                     seg_start);
      }
      if (saved == 0)
        break;
      seg_start = p + 1;
    }
    p++;
  }
  free(work);
}

int32_t start_telnet(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp, telnet_state_t *state) {
  char *empty = "";
  char *login, *pass;
  int32_t password_prompt_seen = 0;
  int32_t username_prompt_seen = 0;
  int32_t password_only = 0;

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  /*
   * Read initial banners to discover which prompt the server uses.
   *
   * This phase must NEVER declare success: no credential has been sent
   * yet, so any structural cue here (a shell-prompt character inside a
   * MOTD, a path in the banner, etc.) cannot prove valid authentication
   * and was a major source of false positives in earlier revisions.
   */
  buf = NULL;
  while ((buf = telnet_receive_response(s, state, buf)) != NULL) {
    make_to_lower(buf);

    if (hydra_strcasestr(buf, "ress ENTER") != NULL) {
      if (hydra_send(s, "\r\n", 2, 0) < 0) {
        free(buf);
        return 4;
      }
      free(buf);
      buf = NULL;
      continue;
    }
    if (is_password_prompt(buf))
      password_prompt_seen = 1;

    if (is_login_prompt_banner(buf))
      username_prompt_seen = 1;

    if (password_prompt_seen && !username_prompt_seen) {
      password_only = 1;
      free(buf);
      buf = NULL;
      break;
    }
    if (username_prompt_seen) {
      free(buf);
      buf = NULL;
      break;
    }
  }
  if (!password_prompt_seen && !username_prompt_seen)
    return 4;

  /* Send username only if not in password-only mode */
  if (!password_only) {
    if (telnet_send_credential(s, login) < 0)
      return 4;

    /*
     * Wait for the server's response after sending the username.
     *
     * Three valid outcomes are recognised here:
     *   - password prompt   -> proceed to send the candidate password
     *   - login re-prompt   -> the username is wrong, advance pair
     *   - explicit failure  -> the username/account is rejected outright
     *   - success           -> the account has no password and the server
     *                          dropped us straight into a shell. This is
     *                          the documented "passwordless account" case
     *                          (Cisco / embedded devices, Unix users with
     *                          an empty password field, etc.) and must be
     *                          reported with the credential pair that
     *                          triggered it. The legacy module behaved
     *                          this way; an earlier refactor lost it.
     */
    int32_t got_password_prompt = 0;
    do {
      if ((buf = telnet_receive_response(s, state, buf)) == NULL)
        return 4;

      (void)make_to_lower(buf);

      switch (classify_response(buf)) {
      case TELNET_RESP_PASSWORD:
        got_password_prompt = 1;
        free(buf);
        buf = NULL;
        break;
      case TELNET_RESP_FAILURE:
        return telnet_failed_pair(state, buf);
      case TELNET_RESP_SUCCESS:
        hydra_report_found_host(port, ip, "telnet", fp);
        hydra_completed_pair_found();
        free(buf);
        if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
          return 3;
        return 1;
      case TELNET_RESP_NONE:
      default:
        break;
      }
    } while (got_password_prompt == 0);
  }

  /* Send password */
  if (telnet_send_credential(s, pass) < 0)
    return 4;

  /*
   * Response handling after the password has been sent.
   *
   * The four cases below are evaluated in the order imposed by
   * classify_response():
   *
   *     failure phrase  >  login re-prompt  >  password re-prompt  >  success
   *
   * Putting success last guarantees that a response containing both a
   * failure phrase and a stray prompt character (e.g. an error banner
   * followed by "Login:") is correctly treated as a failure.
   *
   * Re-prompts belong to the live socket. Password re-prompts are handled
   * here; login/failure re-prompts are passed to the next start_telnet().
   */
  while ((buf = telnet_receive_response(s, state, buf)) != NULL) {
    make_to_lower(buf);

    switch (classify_response(buf)) {
    case TELNET_RESP_FAILURE:
      return telnet_failed_pair(state, buf);

    case TELNET_RESP_PASSWORD:
      hydra_completed_pair();
      free(buf);
      buf = NULL;
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 3;
      if (strlen(pass = hydra_get_next_password()) == 0)
        pass = empty;
      if (telnet_send_credential(s, pass) < 0)
        return 4;
      continue;

    case TELNET_RESP_SUCCESS:
      hydra_report_found_host(port, ip, "telnet", fp);
      hydra_completed_pair_found();
      free(buf);
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 3;
      return 1;

    case TELNET_RESP_NONE:
    default:
      break;
    }

  }

  return 4;
}

void service_telnet(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_TELNET, mysslport = PORT_TELNET_SSL;
  telnet_state_t state = {0};

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  if (miscptr != NULL)
    make_to_lower(miscptr);
  telnet_parse_miscptr(miscptr);

  while (1) {
    switch (run) {
    case 1: /* connect and init */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      no_line_mode = 0;
      free(state.pending_prompt);
      memset(&state, 0, sizeof(state));

      if ((options & OPTION_SSL) == 0) {
        if (port != 0) myport = port;
        sock = hydra_connect_tcp(ip, myport);
        port = myport;
      } else {
        if (port != 0) mysslport = port;
        sock = hydra_connect_ssl(ip, mysslport, hostname);
        port = mysslport;
      }

      if (sock < 0) {
        hydra_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        hydra_child_exit(1);
      }

      /* start_telnet owns the first prompt as well as subsequent reads. */
      next_run = 2;
      break;

    case 2: /* cracking */
      next_run = start_telnet(sock, ip, port, options, miscptr, fp, &state);
      break;

    case 3: /* exit */
      free(state.pending_prompt);
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
      return;

    case 4: /* no authentication decision: EOF, timeout or receive error */
      hydra_report(stderr, "[ERROR] TELNET timed out or closed while waiting for a prompt/response\n");
      free(state.pending_prompt);
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(2);
      return;

    default:
      hydra_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(0);
    }
    run = next_run;
  }
}

int32_t service_telnet_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  return 0;
}

void usage_telnet(const char *service) {
  printf("Module telnet is optionally taking operator-supplied success and/or\n"
         "failure substrings. Providing them is the single most reliable way to\n"
         "avoid false positives and is strongly recommended whenever the\n"
         "target's post-login banner or rejection message is known.\n\n"
         "Optional parameter syntax (all matches are case-insensitive):\n"
         "  <string>                whole value used as a success substring\n"
         "                          (legacy, kept for backwards compatibility)\n"
         "  S=<success>             success substring (response must contain it)\n"
         "  F=<failure>             extra failure substring, in addition to the\n"
         "                          built-in failure phrase list\n"
         "  S=<success>:F=<failure> both at once (order is irrelevant)\n"
         "  \\:                      literal ':' inside a value\n\n"
         "Default success detection (when no S= is supplied):\n"
         " - Requires an explicit failure phrase to be absent\n"
         " - Requires the response to END with a shell prompt character\n"
         "   ('$', '#', '>' or '%%'); prompt characters appearing inside the\n"
         "   buffer are no longer treated as success on their own\n"
         " - Success is never declared before the username has been sent\n"
         " - A passwordless account that drops straight into a shell after\n"
         "   the username is correctly reported as a successful login\n\n"
         "Features:\n"
         " - Automatic password-only mode detection (Cisco, embedded devices)\n"
         " - Passwordless-account detection after username submission\n"
         " - Multilingual prompt support (English, German, Russian, Spanish, ...)\n"
         " - Specific failure-message patterns to minimise misclassification\n"
         " - Operator-defined success/failure overrides via S= / F=\n\n"
         "Examples:\n"
         "  hydra -l root -P pwd.txt ip telnet\n"
         "  hydra -l root -P pwd.txt -m 'S=Last login' ip telnet\n"
         "  hydra -l root -P pwd.txt -m 'F=Authentication failed' ip telnet\n"
         "  hydra -l root -P pwd.txt -m 'S=$ :F=login incorrect' ip telnet\n\n"
         "For password-only servers, use: hydra -l \"\" -P passwords.txt ip telnet\n"
         "For passwordless accounts, combine with -e n to try empty passwords.\n");
}
