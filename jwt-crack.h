#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdbool.h>
#include <pthread.h>
#include "base64.h"

struct s_thread_data {
    EVP_MD *g_evp_md;

    unsigned char *g_result;
    unsigned int g_result_len;

    char *g_buffer;

    char starting_letter;
    size_t max_len;
};

void init_thread_data(struct s_thread_data *data, char starting_letter, size_t max_len);
void destroy_thread_data(struct s_thread_data *data);
bool check(struct s_thread_data *data, const char *secret, size_t secret_len);
bool brute_impl(struct s_thread_data *data, char* str, int index, int max_depth);
char *brute_sequential(struct s_thread_data *data);
void usage(const char *cmd);
