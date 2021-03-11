
/* code original by Jan Dlabal <dlabaljan@gmail.com>, partially rewritten by vh. */

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __sun
#include <sys/int_types.h>
#elif defined(__FreeBSD__) || defined(__IBMCPP__) || defined(_AIX)
#include <inttypes.h>
#else
#include <stdint.h>
#endif
#include "bfg.h"

bf_option bf_options;

#ifdef HAVE_MATH_H

extern int32_t debug;

static int32_t add_single_char(char ch, char flags, int32_t *crs_len) {
  if ((ch >= '2' && ch <= '9') || ch == '0') {
    if ((flags & BF_NUMS) > 0) {
      printf("[ERROR] character %c defined in -x although the whole number "
             "range was already defined by '1', ignored\n",
             ch);
      return 0;
    }
    // printf("[WARNING] adding character %c for -x, note that '1' will add all
    // numbers from 0-9\n", ch);
  }
  if (tolower((int32_t)ch) >= 'b' && tolower((int32_t)ch) <= 'z') {
    if ((ch <= 'Z' && (flags & BF_UPPER) > 0) || (ch > 'Z' && (flags & BF_UPPER) > 0)) {
      printf("[ERROR] character %c defined in -x although the whole letter "
             "range was already defined by '%c', ignored\n",
             ch, ch <= 'Z' ? 'A' : 'a');
      return 0;
    }
    // printf("[WARNING] adding character %c for -x, note that '%c' will add all
    // %scase letters\n", ch, ch <= 'Z' ? 'A' : 'a', ch <= 'Z' ? "up" : "low");
  }
  (*crs_len)++;
  if (BF_CHARSMAX - *crs_len < 1) {
    free(bf_options.crs);
    fprintf(stderr, "Error: charset specification exceeds %d characters.\n", BF_CHARSMAX);
    return 1;
  } else {
    bf_options.crs[*crs_len - 1] = ch;
    bf_options.crs[*crs_len] = '\0';
  }
  return 0;
}
// return values : 0 on success, 1 on error
//
// note that we check for -x .:.:ab but not for -x .:.:ba
//
int32_t bf_init(char *arg) {
  int32_t i = 0;
  int32_t crs_len = 0;
  char flags = 0;
  char *tmp = strchr(arg, ':');

  if (!tmp) {
    fprintf(stderr, "Error: Invalid option format for -x\n");
    return 1;
  } else {
    tmp[0] = '\0';
  }
  bf_options.from = atoi(arg);
  if (bf_options.from < 1 || bf_options.from > 127) {
    fprintf(stderr, "Error: minimum length must be between 1 and 127, format: "
                    "-x min:max:types\n");
    return 1;
  }
  arg = tmp + 1;
  tmp++;
  if (!arg[0]) {
    fprintf(stderr, "Error: no maximum length specified for -x min:max:types!\n");
    return 1;
  }
  tmp = strchr(arg, ':');
  if (!tmp) {
    fprintf(stderr, "Error: Invalid option format for -x\n");
    return 1;
  } else {
    tmp[0] = '\0';
  }
  bf_options.to = atoi(arg);
  tmp++;

  if (bf_options.from > bf_options.to) {
    fprintf(stderr, "Error: you specified a minimum length higher than the "
                    "maximum length!\n");
    return 1;
  }

  if (tmp[0] == 0) {
    fprintf(stderr, "Error: charset not specified!\n");
    return 1;
  }
  bf_options.crs = malloc(sizeof(char) * BF_CHARSMAX);

  if (bf_options.crs == NULL) {
    fprintf(stderr, "Error: can't allocate enough memory!\n");
    return 1;
  }
  bf_options.crs[0] = 0;

  for (; tmp[i]; i++) {
    if (bf_options.disable_symbols) {
      if (add_single_char(tmp[i], flags, &crs_len) == -1)
        return 1;
    } else {
      switch (tmp[i]) {
      case 'a':
        crs_len += 26;
        if (BF_CHARSMAX - crs_len < 1) {
          free(bf_options.crs);
          fprintf(stderr, "Error: charset specification exceeds %d characters.\n", BF_CHARSMAX);
          return 1;
        } else if (flags & BF_LOWER) {
          free(bf_options.crs);
          fprintf(stderr, "Error: 'a' specified more than once in charset!\n");
          return 1;
        } else {
          strcat(bf_options.crs, "abcdefghijklmnopqrstuvwxyz");
          flags |= BF_LOWER;
        }
        break;

      case 'A':
        crs_len += 26;
        if (BF_CHARSMAX - crs_len < 1) {
          free(bf_options.crs);
          fprintf(stderr, "Error: charset specification exceeds %d characters.\n", BF_CHARSMAX);
          return 1;
        } else if (flags & BF_UPPER) {
          free(bf_options.crs);
          fprintf(stderr, "Error: 'A' specified more than once in charset!\n");
          return 1;
        } else {
          strcat(bf_options.crs, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
          flags |= BF_UPPER;
        }
        break;

      case '1':
        crs_len += 10;
        if (BF_CHARSMAX - crs_len < 1) {
          free(bf_options.crs);
          fprintf(stderr, "Error: charset specification exceeds %d characters.\n", BF_CHARSMAX);
          return 1;
        } else if (flags & BF_NUMS) {
          free(bf_options.crs);
          fprintf(stderr, "Error: '1' specified more than once in charset!\n");
          return 1;
        } else {
          strcat(bf_options.crs, "0123456789");
          flags |= BF_NUMS;
        }
        break;

      default:
        if (add_single_char(tmp[i], flags, &crs_len) == -1)
          return 1;
        break;
      }
    }
  }

  bf_options.crs_len = crs_len;
  bf_options.current = bf_options.from;

  memset((char *)bf_options.state, 0, sizeof(bf_options.state));

  if (debug)
    printf("[DEBUG] bfg INIT: from %u, to %u, len: %u, set: %s\n", bf_options.from, bf_options.to, bf_options.crs_len, bf_options.crs);

  return 0;
}

uint64_t bf_get_pcount() {
  int32_t i;
  double count = 0;
  uint64_t foo;

  for (i = bf_options.from; i <= bf_options.to; i++)
    count += (pow((double)bf_options.crs_len, (double)i));
  if (count >= 0xffffffff) {
    fprintf(stderr, "\n[ERROR] definition for password bruteforce (-x) "
                    "generates more than 4 billion passwords - this is not a bug in the program, it is just not feasible to try so many attempts. Try a calculator how long that would take. duh.\n");
    exit(-1);
  }

  foo = count / 1;
  return foo;
}

char *bf_next() {
  int32_t i, pos = bf_options.current - 1;

  if (bf_options.current > bf_options.to)
    return NULL; // we are done

  if ((bf_options.ptr = malloc(BF_CHARSMAX)) == NULL) {
    fprintf(stderr, "Error: Can not allocate memory for -x data!\n");
    return NULL;
  }

  for (i = 0; i < bf_options.current; ++i)
    bf_options.ptr[i] = bf_options.crs[bf_options.state[i]];
  // we don't subtract the same depending on wether the length is odd or even
  bf_options.ptr[bf_options.current] = 0;

  if (debug) {
    printf("[DEBUG] bfg IN: len %u, from %u, current %u, to %u, state:", bf_options.crs_len, bf_options.from, bf_options.current, bf_options.to);
    for (i = 0; i < bf_options.current; i++)
      printf(" %u", bf_options.state[i]);
    printf(", x: %s\n", bf_options.ptr);
  }

  // we revert the ordering of the bruteforce to fix the first static character
  while (pos >= 0 && (++bf_options.state[pos]) >= bf_options.crs_len) {
    bf_options.state[pos] = 0;
    pos--;
  }

  if (pos < 0 || pos >= bf_options.current) {
    bf_options.current++;
    memset((char *)bf_options.state, 0, sizeof(bf_options.state));
  }

  return bf_options.ptr;
}

#endif
