
/* code original by Jan Dlabal <dlabaljan@gmail.com>, partially rewritten by vh */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#include "bfg.h"

bf_option bf_options;

#ifdef HAVE_MATH_H

extern int debug;

// return values : 0 on success, 1 on error
//
// note that we check for -x .:.:ab but not for -x .:.:ba
//
int bf_init(char *arg) {
  int i = 0;
  int crs_len = 0;
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
    fprintf(stderr, "Error: minimum length must be between 1 and 127, format: -x min:max:types\n");
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
    fprintf(stderr, "Error: you specified a minimum length higher than the maximum length!\n");
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
      if ((tmp[i] >= '2' && tmp[i] <= '9') || tmp[i] == '0') {
        if ((flags & BF_NUMS) > 0) {
          printf("[ERROR] character %c defined in -x although the whole number range was already defined by '1', ignored\n", tmp[i]);
          continue;
        }
        printf("[WARNING] adding character %c for -x, note that '1' will add all numbers from 0-9\n", tmp[i]);
      }
      if (tolower((int) tmp[i]) >= 'b' && tolower((int) tmp[i]) <= 'z') {
        if ((tmp[i] <= 'Z' && (flags & BF_UPPER) > 0) || (tmp[i] > 'Z' && (flags & BF_UPPER) > 0)) {
          printf("[ERROR] character %c defined in -x although the whole letter range was already defined by '%c', ignored\n", tmp[i], tmp[i] <= 'Z' ? 'A' : 'a');
          continue;
        }
        printf("[WARNING] adding character %c for -x, note that '%c' will add all %scase letters\n", tmp[i], tmp[i] <= 'Z' ? 'A' : 'a', tmp[i] <= 'Z' ? "up" : "low");
      }
      crs_len++;
      if (BF_CHARSMAX - crs_len < 1) {
        free(bf_options.crs);
        fprintf(stderr, "Error: charset specification exceeds %d characters.\n", BF_CHARSMAX);
        return 1;
      } else {
        bf_options.crs[crs_len - 1] = tmp[i];
        bf_options.crs[crs_len] = '\0';
      }
      break;
    }
  }

  bf_options.crs_len = crs_len;
  bf_options.current = bf_options.from;
  memset((char *) bf_options.state, 0, sizeof(bf_options.state));
  if (debug)
    printf("[DEBUG] bfg INIT: from %d, to %d, len: %d, set: %s\n", bf_options.from, bf_options.to, bf_options.crs_len, bf_options.crs);

  return 0;
}


unsigned long int bf_get_pcount() {
  int i;
  unsigned long int count = 0;

  for (i = bf_options.from; i <= bf_options.to; i++)
    count += (unsigned long int) (pow((float) bf_options.crs_len, (float) i));
  return count;
}


char *bf_next() {
  int i, pos = bf_options.current - 1;

  if (bf_options.current > bf_options.to)
    return NULL;                // we are done

  if ((bf_options.ptr = malloc(BF_CHARSMAX)) == NULL) {
    fprintf(stderr, "Error: Can not allocate memory for -x data!\n");
    return NULL;
  }

  for (i = 0; i < bf_options.current; i++)
    bf_options.ptr[i] = bf_options.crs[bf_options.state[i]];
  bf_options.ptr[bf_options.current] = 0;

  if (debug) {
    printf("[DEBUG] bfg IN: len %d, from %d, current %d, to %d, state:", bf_options.crs_len, bf_options.from, bf_options.current, bf_options.to);
    for (i = 0; i < bf_options.current; i++)
      printf(" %d", bf_options.state[i]);
    printf(", x: %s\n", bf_options.ptr);
  }

  while (pos >= 0 && (++bf_options.state[pos]) >= bf_options.crs_len) {
    bf_options.state[pos] = 0;
    pos--;
  }

  if (pos < 0) {
    bf_options.current++;
    memset((char *) bf_options.state, 0, sizeof(bf_options.state));
  }

  return bf_options.ptr;
}

#endif
