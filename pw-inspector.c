#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROGRAM "PW-Inspector"
#define VERSION "v0.2"
#define EMAIL "vh@thc.org"
#define WEB "https://github.com/vanhauser-thc/thc-hydra"

#define MAXLENGTH 256

char *prg;

void help() {
  printf("%s %s (c) 2005 by van Hauser / THC %s [%s]\n\n", PROGRAM, VERSION, EMAIL, WEB);
  printf("Syntax: %s [-i FILE] [-o FILE] [-m MINLEN] [-M MAXLEN] [-c MINSETS] "
         "-l -u -n -p -s\n\n",
         prg);
  printf("Options:\n");
  printf("  -i FILE    file to read passwords from (default: stdin)\n");
  printf("  -o FILE    file to write valid passwords to (default: stdout)\n");
  printf("  -m MINLEN  minimum length of a valid password\n");
  printf("  -M MAXLEN  maximum length of a valid password\n");
  printf("  -c MINSETS the minimum number of sets required (default: all "
         "given)\n");
  printf("Sets:\n");
  printf("  -l         lowcase characters (a,b,c,d, etc.)\n");
  printf("  -u         upcase characters (A,B,C,D, etc.)\n");
  printf("  -n         numbers (1,2,3,4, etc.)\n");
  printf("  -p         printable characters (which are not -l/-u/-n, e.g. "
         "$,!,/,(,*, etc.)\n");
  printf("  -s         special characters - all others not within the sets "
         "above\n");
  printf("\n%s reads passwords in and prints those which meet the requirements.\n", PROGRAM);
  printf("The return code is the number of valid passwords found, 0 if none "
         "was found.\n");
  printf("Use for security: check passwords, if 0 is returned, reject password "
         "choice.\n");
  printf("Use for hacking: trim your dictionary file to the pw requirements of "
         "the target.\n");
  printf("Usage only allowed for legal purposes.\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  int32_t i, j, k;
  int32_t sets = 0, countsets = 0, minlen = 0, maxlen = MAXLENGTH, count = 0;
  int32_t set_low = 0, set_up = 0, set_no = 0, set_print = 0, set_other = 0;
  FILE *in = stdin, *out = stdout;
  char buf[MAXLENGTH + 1];

  prg = argv[0];
  if (argc < 2)
    help();

  while ((i = getopt(argc, argv, "i:o:m:M:c:lunps")) >= 0) {
    switch (i) {
    case 'i':
      if ((in = fopen(optarg, "r")) == NULL) {
        fprintf(stderr, "Error: unable to open input file %s\n", optarg);
        exit(-1);
      }
      break;
    case 'o':
      if ((out = fopen(optarg, "w")) == NULL) {
        fprintf(stderr, "Error: unable to open output file %s\n", optarg);
        exit(-1);
      }
      break;
    case 'm':
      minlen = atoi(optarg);
      break;
    case 'M':
      maxlen = atoi(optarg);
      break;
    case 'c':
      countsets = atoi(optarg);
      break;
    case 'l':
      if (set_low == 0) {
        set_low = 1;
        sets++;
      }
      break;
    case 'u':
      if (set_up == 0) {
        set_up = 1;
        sets++;
      }
      break;
    case 'n':
      if (set_no == 0) {
        set_no = 1;
        sets++;
      }
      break;
    case 'p':
      if (set_print == 0) {
        set_print = 1;
        sets++;
      }
      break;
    case 's':
      if (set_other == 0) {
        set_other = 1;
        sets++;
      }
      break;
    default:
      help();
    }
  }
  if (minlen > maxlen) {
    fprintf(stderr, "Error: -m MINLEN is greater than -M MAXLEN\n");
    exit(-1);
  }
  if (countsets > sets) {
    fprintf(stderr, "Error: -c MINSETS is larger than the sets defined\n");
    exit(-1);
  }
  if (countsets == 0)
    countsets = sets;

  while (fgets(buf, sizeof(buf), in) != NULL) {
    i = -1;
    if (buf[0] == 0)
      continue;
    if (buf[strlen(buf) - 1] == '\n')
      buf[strlen(buf) - 1] = 0;
    if (buf[strlen(buf) - 1] == '\r')
      buf[strlen(buf) - 1] = 0;
    if (strlen(buf) >= minlen && strlen(buf) <= maxlen) {
      i = 0;
      if (countsets > 0) {
        if (set_low)
          if (strpbrk(buf, "abcdefghijklmnopqrstuvwxyz") != NULL)
            i++;
        if (set_up)
          if (strpbrk(buf, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != NULL)
            i++;
        if (set_no)
          if (strpbrk(buf, "0123456789") != NULL)
            i++;
        if (set_print) {
          j = 0;
          for (k = 0; k < strlen(buf); k++)
            if (isprint((int32_t)buf[k]) != 0 && isalnum((int32_t)buf[k]) == 0)
              j = 1;
          if (j)
            i++;
        }
        if (set_other) {
          j = 0;
          for (k = 0; k < strlen(buf); k++)
            if (isprint((int32_t)buf[k]) == 0 && isalnum((int32_t)buf[k]) == 0)
              j = 1;
          if (j)
            i++;
        }
      }
      if (i >= countsets) {
        fprintf(out, "%s\n", buf);
        count++;
      }
    }
    /* fprintf(stderr, "[DEBUG] i: %d  minlen: %d  maxlen: %d  len: %d\n", i,
     * minlen, maxlen, strlen(buf)); */
  }
  fclose(in);
  fclose(out);

  return count;
}
