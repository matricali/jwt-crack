#include "jwt-crack.h"

char *g_header_b64 = NULL;
char *g_payload_b64 = NULL;
char *g_signature_b64 = NULL;
unsigned char *g_to_encrypt = NULL;
unsigned char *g_signature = NULL;

size_t g_header_b64_len = 0;
size_t g_payload_b64_len = 0;
size_t g_signature_b64_len = 0;
size_t g_signature_len = 0;
size_t g_to_encrypt_len = 0;

char *g_alphabet = NULL;
size_t g_alphabet_len = 0;

char *g_found_secret = NULL;

void init_thread_data(struct s_thread_data *data, char starting_letter, size_t max_len)
{
    data->max_len = max_len;
    data->starting_letter = starting_letter;
	data->g_evp_md = (EVP_MD *) EVP_sha256();
	data->g_result = malloc(EVP_MAX_MD_SIZE);
	data->g_buffer = malloc(max_len + 1);
}

void destroy_thread_data(struct s_thread_data *data)
{
    free(data->g_result);
    free(data->g_buffer);
}

bool check(struct s_thread_data *data, const char *secret, size_t secret_len)
{
    if (g_found_secret != NULL) {
        destroy_thread_data(data);
        pthread_exit(NULL);
    }

    printf(">> %s                                             \r", data->g_buffer);
    fflush(stdout);

	HMAC(
		data->g_evp_md,
		(const unsigned char *) secret, secret_len,
		(const unsigned char *) g_to_encrypt, g_to_encrypt_len,
		data->g_result, &(data->g_result_len)
	);

	return memcmp(data->g_result, g_signature, g_signature_len) == 0;
}

bool brute_impl(struct s_thread_data *data, char* str, int index, int max_depth)
{
    for (int i = 0; i < g_alphabet_len; ++i)
    {
        str[index] = g_alphabet[i];

        if (index == max_depth - 1) {
            if (check(data, (const char *) str, max_depth)) return true;
        } else {
			if (brute_impl(data, str, index + 1, max_depth)) return true;
        }
    }

	return false;
}

char *brute_sequential(struct s_thread_data *data)
{
    data->g_buffer[0] = data->starting_letter;

    // if (check(data, data->g_buffer, 1)) {
    //     g_found_secret = strndup(data->g_buffer, 1);
    //     return g_found_secret;
    // }

    // for (size_t i = 2; i <= data->max_len; ++i) {
    for (size_t i = 6; i <= data->max_len; ++i) {
      	if (brute_impl(data, data->g_buffer, 1, i)) {
            g_found_secret = strndup(data->g_buffer, i);
            return g_found_secret;
        }
    }

    success:
        return NULL;
}

void usage(const char *cmd)
{
	printf("%s <token> [letras] [tamano]\n"
		   "Defaults: tamano=6, "
		   "letras=eariotnslcudpmhgbfywkvxzjqEARIOTNSLCUDPMHGBFYWKVXZJQ0123456789", cmd);
}

int main(int argc, char **argv)
{
	size_t max_len = 6;
    // g_alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	g_alphabet = "eariotnslcudpmhgbfywkvxzjqEARIOTNSLCUDPMHGBFYWKVXZJQ0123456789";

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	char *jwt = argv[1];

	if (argc > 2) {
		g_alphabet = argv[2];
    }
	if (argc > 3) {
		max_len = (size_t) atoi(argv[3]);
    }

	g_alphabet_len = strlen(g_alphabet);

	g_header_b64 = strtok(jwt, ".");
	g_payload_b64 = strtok(NULL, ".");
	g_signature_b64 = strtok(NULL, ".");
	g_header_b64_len = strlen(g_header_b64);
	g_payload_b64_len = strlen(g_payload_b64);
	g_signature_b64_len = strlen(g_signature_b64);

	g_to_encrypt_len = g_header_b64_len + 1 + g_payload_b64_len;
	g_to_encrypt = (unsigned char *) malloc(g_to_encrypt_len + 1);
	sprintf((char *) g_to_encrypt, "%s.%s", g_header_b64, g_payload_b64);

	g_signature_len = Base64decode_len((const char *) g_signature_b64);
	g_signature = malloc(g_signature_len);
	g_signature_len = Base64decode((char *) g_signature, (const char *) g_signature_b64);


    struct s_thread_data *pointers_data[g_alphabet_len];
    pthread_t *tid = malloc(g_alphabet_len * sizeof(pthread_t));

    int MAX_THREADS = 24;
    // for (size_t i = 0; i < g_alphabet_len; i++) {
    for (size_t i = 0; i < MAX_THREADS; i++) {
        pointers_data[i] = malloc(sizeof(struct s_thread_data));
        init_thread_data(pointers_data[i], g_alphabet[i], max_len);
        pthread_create(&tid[i], NULL, (void *(*)(void *)) brute_sequential, pointers_data[i]);
    }

    // for (size_t i = 0; i < g_alphabet_len; i++) {
    for (size_t i = 0; i < MAX_THREADS; i++) {
        pthread_join(tid[i], NULL);
    }

	if (g_found_secret == NULL) {
		printf("No encontre nada :(\n");
	} else {
		printf("El secret es: \"%s\"\n", g_found_secret);
    }

    free(g_found_secret);
    free(tid);

	return 0;
}
