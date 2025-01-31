// License: GPLv3
// Created by: Ibn Aleem (github.com/ibnaleem)
// Issues: https://github.com/ibnaleem/hashtable/issues

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

char *sha1_hash(const char *str, size_t length) {
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char *)str, length, digest);

    char *mdString = malloc(SHA_DIGEST_LENGTH * 2 + 1);
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(&mdString[i * 2], "%02x", digest[i]);
    }
    return mdString;
} // sha1_hash

char *md5_hash(const char *str, size_t length)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_md5();
    unsigned int digest_len;

    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, str, length);
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);

    char *mdString = malloc(digest_len * 2 + 1);
    for (unsigned int i = 0; i < digest_len; i++) {
        sprintf(&mdString[i * 2], "%02x", digest[i]);
    }
    return mdString;
} // md5_hash

char *sha256_hash(const char *str, size_t length) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)str, length, digest);

    char *mdString = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&mdString[i * 2], "%02x", digest[i]);
    }
    return mdString;
} // sha256_hash

char *sha512_hash(const char *str, size_t length) {
    unsigned char digest[SHA512_DIGEST_LENGTH];
    SHA512((const unsigned char *)str, length, digest);

    char *mdString = malloc(SHA512_DIGEST_LENGTH * 2 + 1);

    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(&mdString[i * 2], "%02x", digest[i]);
    }

    return mdString;
} // sha512_hash

char *generate_output_filename(const char *input_filename, const char *hash_type) {
    const char *dot = strrchr(input_filename, '.');
    char *output = malloc(256);
    if (!output)
        return NULL;

    if (dot != NULL) {
        int base_length = dot - input_filename;
        snprintf(output, 256, "%.*s_%s%s", base_length, input_filename, hash_type, dot);
    }
    else {
        snprintf(output, 256, "%s_%s", input_filename, hash_type);
    }
    return output;
} // generate_output_filename

int write_to_file(const char *input_filename, char *hash_type)
{
    printf("[*] Computing hashtable for %s using %s algorithm\n", input_filename, hash_type);

    char *output_filename = generate_output_filename(input_filename, hash_type);

    if (!output_filename)
    {
        fprintf(stderr, "Error generating output filename\n");
        return -1;
    }

    FILE *input_file = fopen(input_filename, "r");
    FILE *output_file = fopen(output_filename, "w");

    if (!input_file || !output_file)
    {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    while ((read = getline(&line, &len, input_file)) != -1)
    {
        // Remove the newline character if it exists
        if (line[read - 1] == '\n')
        {
            line[read - 1] = '\0';
            read--; // Adjust length for hashing
        }

        char *hashed_line = NULL;

        if (strcmp(hash_type, "md5") == 0)
        {
            hashed_line = md5_hash(line, read);
        }
        else if (strcmp(hash_type, "sha1") == 0)
        {
            hashed_line = sha1_hash(line, read);
        }
        else if (strcmp(hash_type, "sha256") == 0)
        {
            hashed_line = sha256_hash(line, read);
        }
        else if (strcmp(hash_type, "sha512") == 0)
        {
            hashed_line = sha512_hash(line, read);
        }
        else
        {
            free(output_filename);
            fclose(input_file);
            fclose(output_file);
            return -1;
        }

        fprintf(output_file, "%s:%s\n", hashed_line, line); // Added newline for clarity
        free(hashed_line);                                  // Free allocated memory for hashed line
    } // while-loop

    free(line);
    printf("[+] Successfully computed hashtable: %s\n", output_filename);
    free(output_filename);
    fclose(input_file);
    fclose(output_file);

    return 0;
} // write_to_file

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <input_file> <hash_type>\n", argv[0]);
        return 1;
    }

    char *input_filename = argv[1];
    char *hash_type = argv[2];

    write_to_file(input_filename, hash_type);
    return 0;
} // main