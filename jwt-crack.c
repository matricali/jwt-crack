#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define JWT_CRACK_VERSION "0.1.0"

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

}
