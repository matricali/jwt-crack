#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "base64.h"

#define JWT_CRACK_VERSION "0.2.0"

unsigned char* generate_signature(const char *b64_header,
    const char *b64_payload, const char *secret, unsigned int *out_len);

int verify(const char *b64_header, const char *b64_payload,
    const unsigned char *signature, const char *secret);

void permutation(const char *chars, size_t max_len, const char *cur);


char *g_alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
int g_max_length = 6;


void usage(const char *p)
{
    printf("\nusage: %s [-h] [-a ALPHABET] [-l MAX_LENGTH] <TOKEN>\n", p);
}

int main(int argc, char **argv)
{
    int opt;
    char *input_token = NULL;

    char *jwt_header = NULL;
    char *jwt_payload = NULL;
    char *jwt_signature = NULL;

    unsigned char *jwt_signature_decoded = NULL;
    size_t len = 0;
    size_t rlen = 0;

    printf("\tjwt-crack v%s - (c) 2017 Jorge Matricali\n", JWT_CRACK_VERSION);

    if (argc < 2) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    while ((opt = getopt(argc, argv, "a:l:h")) != -1) {
        switch (opt) {
            case 'a':
                g_alphabet = optarg;
                break;
            case 'l':
                g_max_length = atoi(optarg);
                break;
            case 'h':
                usage(argv[0]);
                exit(EXIT_SUCCESS);
            default:
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (optind < argc) {
        input_token = argv[optind];
    }

    if (strlen(input_token) <= 0) {
        fprintf(stderr, "Invalid token.\n");
        exit(EXIT_FAILURE);
    }

    if (strlen(g_alphabet) <= 0) {
        fprintf(stderr, "Invalid alphabet.\n");
        exit(EXIT_FAILURE);
    }

    if (g_max_length <= 0) {
        fprintf(stderr, "Invalid length.\n");
        exit(EXIT_FAILURE);
    }

    jwt_header = strtok(input_token, ".");
    jwt_payload = strtok(NULL, ".");
    jwt_signature = strtok(NULL, ".");

    if (jwt_signature == NULL) {
        fprintf(stderr, "Invalid token signature.\n");
        exit(EXIT_FAILURE);
    }


    len = strlen(jwt_signature);
    /* Si la cadena base64 no termina con = no nos sirve */
    if (strcmp(jwt_signature + len - 1, "=") != 0) {
        char *tmp = malloc(sizeof(char) * (len + 2));
        if (tmp == NULL) {
            fprintf(stderr, "Insuficient memory!\n");
            exit(EXIT_FAILURE);
        }
        strcpy(tmp, jwt_signature);
        tmp[len] = '=';
        len++;
        tmp[len] = '\0';
        jwt_signature = tmp;
    }

    jwt_signature_decoded = base64_decode((const unsigned char *) jwt_signature, len, &rlen);

    char *secret = "abc123";

    if (verify(jwt_header, jwt_payload, jwt_signature_decoded, secret) == 0) {
        printf("The secret is: %s\n", secret);
    } else {
        printf("Invalid secret.\n");
    }

    free(jwt_signature_decoded);

    permutation(g_alphabet, 6, "");

    return 0;
}

unsigned char* generate_signature(const char *b64_header,
    const char *b64_payload, const char *secret, unsigned int *out_len)
{
    size_t data_len = 0;
    unsigned char *data;
    unsigned char* digest;

    data_len = strlen(b64_header) + 1 + strlen(b64_payload);
    data = (unsigned char *) malloc(data_len + 1);
    sprintf((char *) data, "%s.%s", b64_header, b64_payload);

    EVP_MD *evp_md = (EVP_MD *) EVP_sha256();
    digest = malloc(EVP_MAX_MD_SIZE);

    HMAC(
		evp_md,
		secret, strlen(secret),
		(unsigned char *) data, data_len,
		digest, out_len
	);

    free(data);
    return digest;
}

int verify(const char *b64_header, const char *b64_payload,
    const unsigned char *o_signature, const char *secret)
{
    unsigned int out_len = 0;
    unsigned char *signature = NULL;

    signature = generate_signature(b64_header, b64_payload, secret, &out_len);

    if (!signature) {
        return -1;
    }

    if (memcmp(signature, o_signature, strlen((char *)o_signature)) == 0) {
        free(signature);
        return 0;
    }

    free(signature);
    return -1;
}

void permutation(const char *chars, size_t max_len, const char *cur)
{
    size_t len = 0;

    if (strlen(cur) >= max_len) {
        return;
    }

    len = strlen(chars);

    for (int i = 0; i < len; ++i) {
        char next[max_len];
        sprintf(next, "%s%c", cur, g_alphabet[i]);
        printf(">> %s\n", next);
        permutation(chars, max_len, next);
    }
}
