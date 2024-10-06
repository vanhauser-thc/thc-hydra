// dpl4hydra.c
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2012 Roland Kessler (@rokessler)
// Copyright (c) 2024 Volker Schwaberow

#include <ctype.h>
#include <curl/curl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_LINE_LENGTH 2048
#define MAX_FILENAME_LENGTH 256
#define MAX_FIELD_LENGTH 256
#define MAX_THREADS 8
#define MAX_VENDORS 1000
#define HREF_PREFIX_LENGTH 24
#define COLUMN_WIDTH 25
#define NUM_COLUMNS 2
#define TABLE_WIDTH (COLUMN_WIDTH * NUM_COLUMNS + NUM_COLUMNS + 1)
#define BRANDS_PER_PAGE 20

#define BOX_HORIZONTAL "─"
#define BOX_VERTICAL "│"
#define BOX_TOP_LEFT "┌"
#define BOX_TOP_RIGHT "┐"
#define BOX_BOTTOM_LEFT "└"
#define BOX_BOTTOM_RIGHT "┘"
#define BOX_T_DOWN "┬"
#define BOX_T_UP "┴"
#define BOX_T_RIGHT "├"
#define BOX_T_LEFT "┤"
#define BOX_CROSS "┼"

const char *SITE = "https://cirt.net/passwords";
const char *FULLFILE = "dpl4hydra_full.csv";
const char *OLDFILE = "dpl4hydra_full.old";
const char *LOCALFILE = "dpl4hydra_local.csv";
const char *INDEXSITE = "dpl4hydra_index.tmp";
const char *SUBSITES = "dpl4hydra_subs.tmp";
const char *CLEANFILE = "dpl4hydra_clean.tmp";

typedef struct {
  const char *url;
  const char *filename;
} DownloadTask;

typedef struct {
  char vendor[MAX_FIELD_LENGTH];
  char system[MAX_FIELD_LENGTH];
  char url[MAX_FIELD_LENGTH];
  char username[MAX_FIELD_LENGTH];
  char password[MAX_FIELD_LENGTH];
} VendorEntry;

void usage(const char *program_name);
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp);
void *download_file_thread(void *arg);
void download_files_parallel(DownloadTask *tasks, int num_tasks);
void refresh();
void generate(const char *brand);
int case_insensitive_search(const char *haystack, const char *needle);
void parse_vendor_page(const char *filename, const char *vendor);
void clean_string(char *str);

void usage(const char *program_name) {
  printf("dpl4hydra v1.0.0 (c) 2024\n\n");
  printf("(c) 2012 Roland Kessler (@rokessler)\n");
  printf("(c) 2024 Volker Schwaberow <volker@schwaberow.de>\n\n");
  printf("Syntax: %s [help] | [refresh] | [list] | [BRAND] | [all]\n\n", program_name);
  printf("Options:\n");
  printf("  help        Show this help message\n");
  printf("  refresh     Download and refresh the full default password list\n");
  printf("  list        List all available brands\n");
  printf("  BRAND       Generate a default password list for a specific BRAND\n");
  printf("  all         Generate a list of all system credentials\n\n");
  printf("Example:\n");
  printf("  %s linksys\n", program_name);
}

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
  size_t realsize = size * nmemb;
  FILE *fp = (FILE *)userp;
  return fwrite(contents, size, nmemb, fp);
}

void print_horizontal_line(const char *left, const char *middle, const char *right) {
  printf("%s", left);
  for (int i = 0; i < NUM_COLUMNS; i++) {
    for (int j = 0; j < COLUMN_WIDTH; j++) {
      printf("%s", BOX_HORIZONTAL);
    }
    if (i < NUM_COLUMNS - 1) {
      printf("%s", middle);
    }
  }
  printf("%s\n", right);
}

void print_word_wrapped(const char *text, int width) {
  int len = strlen(text);
  printf("%-*.*s", width, width, text);
  if (len > width) {
    printf("...");
  }
}

void list_brands() {
  FILE *input = fopen(FULLFILE, "r");
  if (!input) {
    fprintf(stderr, "Error: Cannot open input file %s.\n", FULLFILE);
    exit(1);
  }

  char line[MAX_LINE_LENGTH];
  char brand[MAX_FIELD_LENGTH];
  char prev_brand[MAX_FIELD_LENGTH] = "";
  char **brands = NULL;
  int brand_count = 0;
  int capacity = 10;

  brands = malloc(capacity * sizeof(char *));
  if (!brands) {
    fprintf(stderr, "Error: Memory allocation failed.\n");
    fclose(input);
    exit(1);
  }

  while (fgets(line, sizeof(line), input)) {
    if (sscanf(line, "%[^,]", brand) == 1) {
      if (strcmp(brand, prev_brand) != 0) {
        if (brand_count >= capacity) {
          capacity *= 2;
          char **temp = realloc(brands, capacity * sizeof(char *));
          if (!temp) {
            fprintf(stderr, "Error: Memory reallocation failed.\n");
            fclose(input);
            for (int i = 0; i < brand_count; i++) {
              free(brands[i]);
            }
            free(brands);
            exit(1);
          }
          brands = temp;
        }
        brands[brand_count] = strdup(brand);
        if (!brands[brand_count]) {
          fprintf(stderr, "Error: Memory allocation failed for brand.\n");
          fclose(input);
          for (int i = 0; i < brand_count; i++) {
            free(brands[i]);
          }
          free(brands);
          exit(1);
        }
        strcpy(prev_brand, brand);
        brand_count++;
      }
    }
  }

  fclose(input);

  int total_brands = brand_count;
  int filtered_brand_count = brand_count;
  int current_page = 1;
  int start_index = 0;
  char search_term[MAX_FIELD_LENGTH] = "";
  int search_mode = 0;

  while (1) {
    if (search_mode) {
      filtered_brand_count = 0;
      for (int i = 0; i < brand_count; i++) {
        if (case_insensitive_search(brands[i], search_term)) {
          filtered_brand_count++;
        }
      }
    }

    int total_pages = (filtered_brand_count + BRANDS_PER_PAGE - 1) / BRANDS_PER_PAGE;
    if (total_pages == 0)
      total_pages = 1;

    printf("Available brands");
    if (search_mode) {
      printf(" (filtered by: %s)", search_term);
    }
    printf(" (Page %d of %d):\n\n", current_page, total_pages);

    print_horizontal_line(BOX_TOP_LEFT, BOX_T_DOWN, BOX_TOP_RIGHT);

    int displayed_brands = 0;
    int filtered_index = 0;
    for (int i = 0; i < brand_count && displayed_brands < BRANDS_PER_PAGE; i++) {
      if (!search_mode || case_insensitive_search(brands[i], search_term)) {
        if (filtered_index >= start_index) {
          if (displayed_brands % NUM_COLUMNS == 0 && displayed_brands > 0) {
            printf("%s\n", BOX_VERTICAL);
            print_horizontal_line(BOX_T_RIGHT, BOX_CROSS, BOX_T_LEFT);
          }
          printf("%s ", BOX_VERTICAL);
          print_word_wrapped(brands[i], COLUMN_WIDTH - 2);
          printf(" ");
          displayed_brands++;
        }
        filtered_index++;
      }
    }

    while (displayed_brands % NUM_COLUMNS != 0) {
      printf("%s %-*s ", BOX_VERTICAL, COLUMN_WIDTH - 2, "");
      displayed_brands++;
    }
    printf("%s\n", BOX_VERTICAL);

    print_horizontal_line(BOX_BOTTOM_LEFT, BOX_T_UP, BOX_BOTTOM_RIGHT);

    printf("\nTotal number of brands: %d", filtered_brand_count);
    if (search_mode) {
      printf(" (filtered from %d)", total_brands);
    }
    printf("\n\n");

    printf("Enter 'n' for next page, 'p' for previous page, 's' to search, 'c' to clear search, or 'q' to quit: ");
    char choice;
    scanf(" %c", &choice);

    switch (choice) {
    case 'n':
      if (current_page < total_pages) {
        current_page++;
        start_index += BRANDS_PER_PAGE;
      }
      break;
    case 'p':
      if (current_page > 1) {
        current_page--;
        start_index -= BRANDS_PER_PAGE;
      }
      break;
    case 's':
      printf("Enter search term: ");
      scanf("%s", search_term);
      search_mode = 1;
      current_page = 1;
      start_index = 0;
      break;
    case 'c':
      search_mode = 0;
      current_page = 1;
      start_index = 0;
      break;
    case 'q':
      return;
    default:
      printf("Invalid choice. Please try again.\n");
    }
  }

  printf("\033[2J\033[H");

  for (int i = 0; i < brand_count; i++) {
    free(brands[i]);
  }
  free(brands);
}

void *download_file_thread(void *arg) {
  DownloadTask *task = (DownloadTask *)arg;
  CURL *curl;
  FILE *fp;
  CURLcode res;

  curl = curl_easy_init();
  if (curl) {
    fp = fopen(task->filename, "wb");
    curl_easy_setopt(curl, CURLOPT_URL, task->url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    fclose(fp);

    if (res != CURLE_OK) {
      fprintf(stderr, "Error: Download failed for %s - %s\n", task->url, curl_easy_strerror(res));
    }
  }
  return NULL;
}

void download_files_parallel(DownloadTask *tasks, int num_tasks) {
  pthread_t threads[MAX_THREADS];
  int i, thread_index = 0;

  for (i = 0; i < num_tasks; i++) {
    pthread_create(&threads[thread_index], NULL, download_file_thread, &tasks[i]);
    thread_index = (thread_index + 1) % MAX_THREADS;

    if (thread_index == 0 || i == num_tasks - 1) {
      for (int j = 0; j < MAX_THREADS && j <= i; j++) {
        pthread_join(threads[j], NULL);
      }
    }
  }
}

void clean_string(char *str) {
  char *src = str;
  char *dst = str;

  while (*src) {
    if (*src != '\r' && *src != '\n' && *src != '\t') {
      *dst = *src;
      dst++;
    }
    src++;
  }
  *dst = '\0';
}

void parse_vendor_page(const char *filename, const char *vendor) {
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    fprintf(stderr, "Error: Cannot open file %s\n", filename);
    return;
  }

  FILE *out = fopen(FULLFILE, "a");
  if (!out) {
    fprintf(stderr, "Error: Cannot open file %s for writing\n", FULLFILE);
    fclose(fp);
    return;
  }

  char line[MAX_LINE_LENGTH];
  char username[256], password[256], url[256], system[256];

  while (fgets(line, sizeof(line), fp)) {
    clean_string(line);
    if (sscanf(line, "%*[^>]>%255[^<]</td>%*[^>]>%255[^<]</td>%*[^>]>%255[^<]</td>%*[^>]>%255[^<]", username, password, url, system) == 4) {
      fprintf(out, "%s,%s,%s,%s,%s,%s\n", vendor, system, url, "", username, password);
    }
  }

  fclose(fp);
  fclose(out);
}

void refresh() {
  printf("Refreshing password list...\n");

  DownloadTask index_task = {SITE, INDEXSITE};
  download_files_parallel(&index_task, 1);

  FILE *index_file = fopen(INDEXSITE, "r");
  if (!index_file) {
    fprintf(stderr, "Error: Cannot open index file\n");
    return;
  }

  char line[MAX_LINE_LENGTH];
  char vendor_urls[MAX_VENDORS][256];
  char vendor_names[MAX_VENDORS][64];
  int vendor_count = 0;

  while (fgets(line, sizeof(line), index_file) && vendor_count < MAX_VENDORS) {
    char *start = strstr(line, "href=\"/passwords?vendor=");
    if (start) {
      start += HREF_PREFIX_LENGTH;
      char *end = strchr(start, '"');
      if (end) {
        *end = '\0';
        snprintf(vendor_urls[vendor_count], sizeof(vendor_urls[vendor_count]), "https://cirt.net/passwords?vendor=%s", start);
        strncpy(vendor_names[vendor_count], start, sizeof(vendor_names[vendor_count]));
        vendor_count++;
      }
    }
  }
  fclose(index_file);

  printf("Found %d vendors. Downloading vendor pages...\n", vendor_count);

  DownloadTask *vendor_tasks = malloc(vendor_count * sizeof(DownloadTask));
  for (int i = 0; i < vendor_count; i++) {
    vendor_tasks[i].url = vendor_urls[i];
    vendor_tasks[i].filename = malloc(MAX_FILENAME_LENGTH);
    snprintf((char *)vendor_tasks[i].filename, MAX_FILENAME_LENGTH, "vendor_%s.html", vendor_names[i]);
  }

  download_files_parallel(vendor_tasks, vendor_count);

  if (access(FULLFILE, F_OK) != -1) {
    rename(FULLFILE, OLDFILE);
  }

  for (int i = 0; i < vendor_count; i++) {
    parse_vendor_page(vendor_tasks[i].filename, vendor_names[i]);
    remove(vendor_tasks[i].filename);
    free((void *)vendor_tasks[i].filename);
  }
  free(vendor_tasks);

  printf("Refreshed password list created.\n");
}

int case_insensitive_search(const char *haystack, const char *needle) {
  const char *p1 = haystack, *p2 = needle;
  while (*p1 && *p2) {
    if (tolower((unsigned char)*p1) != tolower((unsigned char)*p2))
      return 0;
    p1++;
    p2++;
  }
  return *p2 == '\0';
}

void generate(const char *brand) {
  char output_filename[MAX_FILENAME_LENGTH];
  snprintf(output_filename, sizeof(output_filename), "dpl4hydra_%s.lst", brand);

  FILE *input = fopen(FULLFILE, "r");
  FILE *output = fopen(output_filename, "w");

  if (!input || !output) {
    fprintf(stderr, "Error: Cannot open input or output file.\n");
    exit(1);
  }

  char line[MAX_LINE_LENGTH];
  int entries = 0;
  int all_brands = strcmp(brand, "all") == 0;

  while (fgets(line, sizeof(line), input)) {
    if (all_brands || case_insensitive_search(line, brand)) {
      char *username = strchr(line, ',');
      if (username) {
        username = strchr(username + 1, ',');
        if (username) {
          username = strchr(username + 1, ',');
          if (username) {
            username = strchr(username + 1, ',');
            if (username) {
              char *password = strchr(username + 1, ',');
              if (password) {
                *password = '\0';
                password++;
                char *end = strchr(password, ',');
                if (end)
                  *end = '\0';

                username++;
                if (*username && *password) {
                  fprintf(output, "%s:%s\n", username, password);
                  entries++;
                }
              }
            }
          }
        }
      }
    }
  }

  fclose(input);
  fclose(output);

  printf("File %s was created with %d entries.\n", output_filename, entries);
}

void cleanup() {
  remove(INDEXSITE);
  remove(SUBSITES);
  remove(CLEANFILE);
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    usage(argv[0]);
    return 1;
  }

  curl_global_init(CURL_GLOBAL_ALL);

  if (strcmp(argv[1], "help") == 0) {
    usage(argv[0]);
  } else if (strcmp(argv[1], "refresh") == 0) {
    refresh();
  } else if (strcmp(argv[1], "list") == 0) {
    list_brands();
  } else if (strcmp(argv[1], "all") == 0) {
    generate("all");
  } else {
    generate(argv[1]);
  }

  curl_global_cleanup();
  cleanup();
  return 0;
}