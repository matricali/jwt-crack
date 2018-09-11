#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "base64.h"

#define JWT_CRACK_VERSION "0.1.0"

char *g_alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
int g_max_length = 6;


void usage(const char *p)
{
    printf("\nusage: %s [-h] [-a ALPHABET] [-l MAX_LENGTH] <TOKEN>\n", p);
}

unsigned char* generate_signature(const char *b64_header, const char *b64_payload,
    const char *secret, unsigned int *out_len)
{
    // char *data = strdup(b64_header);
    // strcat(data, ".");
    // strcat(data, b64_payload);
    size_t data_len = 0;
    unsigned char *data;

    data_len = strlen(b64_header) + 1 + strlen(b64_payload);
    data = (unsigned char *) malloc(data_len + 1);
    sprintf((char *) data, "%s.%s", b64_header, b64_payload);

    unsigned char* digest;
    // unsigned int digest_len;

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

static const int B64index[256] = { 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 62, 63, 62, 62, 63, 52, 53, 54, 55,
56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,  0,  0,  1,  2,  3,  4,  5,  6,
7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,
0,  0,  0, 63,  0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51 };

char *b64decode(const void* data, const size_t len)
{
    unsigned char* p = (unsigned char*)data;
    int pad = len > 0 && (len % 4 || p[len - 1] == '=');
    const size_t L = ((len + 3) / 4 - pad) * 4;
    char *str(L / 4 * 3 + pad, '\0');

    for (size_t i = 0, j = 0; i < L; i += 4)
    {
        int n = B64index[p[i]] << 18 | B64index[p[i + 1]] << 12 | B64index[p[i + 2]] << 6 | B64index[p[i + 3]];
        str[j++] = n >> 16;
        str[j++] = n >> 8 & 0xFF;
        str[j++] = n & 0xFF;
    }
    if (pad)
    {
        int n = B64index[p[L]] << 18 | B64index[p[L + 1]] << 12;
        str[strlen(str) - 1] = n >> 16;

        if (len > L + 2 && p[L + 2] != '=')
        {
            n |= B64index[p[L + 2]] << 6;
            str.push_back(n >> 8 & 0xFF);
        }
    }
    return str;
}

int main(int argc, char **argv)
{
    int opt;
    char *input_token = NULL;

    char *jwt_header = NULL;
    char *jwt_payload = NULL;
    char *jwt_signature = NULL;

    printf("\tjwt-crack v%s\n", JWT_CRACK_VERSION);

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

    printf("alphabet=%s\nlength=%d\ntoken=%s\n", g_alphabet, g_max_length, input_token);

    jwt_header = strtok(input_token, ".");
    jwt_payload = strtok(NULL, ".");
    jwt_signature = strtok(NULL, ".");

    if (jwt_signature == NULL) {
        fprintf(stderr, "Invalid token signature.\n");
        exit(EXIT_FAILURE);
    }

    printf("\nTOKEN DATA:\nheader=%s\npayload=%s\nsignature=%s\n", jwt_header, jwt_payload, jwt_signature);

    size_t out_len = 0;
    // char *jwt_header_decoded = (char *) base64_decode((const unsigned char *) jwt_header, strlen(jwt_header), &out_len);
    // char *jwt_payload_decoded = (char *) base64_decode((const unsigned char *) jwt_payload, strlen(jwt_payload), &out_len);
    char *jwt_signature_decoded = NULL;

    jwt_signature_decoded = (char *) base64_decode((const unsigned char *) jwt_signature, strlen(jwt_signature), &out_len);
    // printf("%s\n", jwt_signature_decoded);
    // exit(0);
    // printf("\nDECODED DATA:\nheader=%s\npayload=%s\nsignature=%s\n", jwt_header_decoded, jwt_payload_decoded, jwt_signature_decoded);

    unsigned char *ret = NULL;
    unsigned int ret_len = 0;
    char *secret = "pl4y3r";

    ret = generate_signature(jwt_header, jwt_payload, secret, &ret_len);
    // ret = base64_encode(ret, strlen((char *)ret), &out_len);
    if (memcmp(ret, jwt_signature_decoded, strlen(jwt_signature_decoded)) == 0) {
        printf("The secret is: %s\n", secret);
    } else {
        printf("Invalid secret.\n");
    }
    printf("HMAC=%s\n", ret);

    return 0;
}
