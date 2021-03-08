#include <string.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// link it with: -lcrypto -lssl

void hex_dump(const void *data, unsigned size, const unsigned cols, bool numbers)
{
    if (!data || !size)
    {
        printf("Nothing to dump\n");
        return;
    }

    printf("(%u %s)", size, size > 1 ? "bytes" : "byte");
    if (!cols)
    {
        printf("\n%.*s\n", (int)size, (const char*)data);
        return;
    }

    auto ptr = (const unsigned char*)data;
    unsigned i, c;
    for (c = i = 0; i < size; ++i)
    {
        if (i < c)
            printf(" %02X", ptr[i]);
        else
        {
            if (!numbers) printf("\n%02X", ptr[i]);
            else printf("\n%08X: %02X", c, ptr[i]);
            c += cols;
        }
    }

    printf("\n");
}

unsigned long file_get_contents(const char* filename, unsigned char** out, unsigned long limit = 0)
{
    unsigned long len = 0;
    if (!filename)
        return len;

    auto f = fopen(filename, "rb");
    if (!f)
        return len;

    fseek(f, 0, SEEK_END);
    len = ftell(f);

    if (!len || !out)
    {
        fclose(f);
        return len;
    }
    rewind(f);

    if (limit > 0 && len > limit)
        len = limit;

    *out = (unsigned char*)realloc(*out, len);
    if (!*out)
    {
        fclose(f);
        return 0;
    }

    limit = len;
    while(limit > 0)
    {
        auto done = fread(*out, 1, limit, f);
        if (!done)
        {// some shit happened
            fclose(f);
            return len - limit;
        }
        limit -= done;
    }

    fclose(f);
    return len; // don't forget to free(*out) after use
}

bool update_hash_from_file(const char* filename, unsigned digest_size, void* hasher)
{
    if (!hasher)
        return false;

    auto file = fopen(filename, "rb");
    if (!file)
        return false;

    unsigned char buf[16];
    long len;

    switch(digest_size)
    {
        case SHA256_DIGEST_LENGTH:
            while(0 < (len = fread(buf, 1, 16, file)))
                SHA256_Update((SHA256_CTX*)hasher, buf, len);
            break;
        case SHA384_DIGEST_LENGTH:
            while(0 < (len = fread(buf, 1, 16, file)))
                SHA384_Update((SHA512_CTX*)hasher, buf, len);
            break;
        case SHA512_DIGEST_LENGTH:
            while(0 < (len = fread(buf, 1, 16, file)))
                SHA512_Update((SHA512_CTX*)hasher, buf, len);
            break;
        default:
            fclose(file);
            return false;
    }

    fclose(file);
    return true;
}

bool equal(unsigned long size, const unsigned char* buf1, const unsigned char* buf2)
{
    while(size--> 0)
        if (buf1[size] != buf2[size])
            return false;

    return true;
}

int main()
{   // preparing data to sign with SHA-384 hash (bacause cipher suite is TLS_AES_256_GCM_SHA384)
    SHA512_CTX msg_hasher;
    unsigned digest_size = SHA384_DIGEST_LENGTH;

    SHA384_Init(&msg_hasher);
    if (!update_hash_from_file("./files/ClientHello", digest_size, &msg_hasher) ||
        !update_hash_from_file("./files/ServerHello", digest_size, &msg_hasher) || 
        !update_hash_from_file("./files/Encrypt_Ext", digest_size, &msg_hasher) ||
        !update_hash_from_file("./files/Certificate", digest_size, &msg_hasher))
    {
        printf("File(s) not found\n");
        return -1;
    }

    const char* info = "TLS 1.3, server CertificateVerify";
    unsigned len = strlen(info);
    unsigned char sign_data[65 + len + digest_size];

    memset(sign_data, 0x20, 64);
    memcpy(sign_data + 64, info, len);
    len += 64;
    sign_data[len++] = 0;

    SHA384_Final(sign_data + len, &msg_hasher);
    len += digest_size;

    printf("Data to sign -> ");
    hex_dump(sign_data, len, 32, 0);

    // preparing SHA-256 digest to use in signature (signature scheme is rsa_pss_rsae_sha256)
    auto sig_hasher = (SHA256_CTX*)&msg_hasher;
    digest_size = SHA256_DIGEST_LENGTH;
    SHA256_Init(sig_hasher);
    SHA256_Update(sig_hasher, sign_data, len);
    SHA256_Final(sign_data, sig_hasher);

    printf("Digest to sign: ");
    hex_dump(sign_data, digest_size, digest_size, 0);

    // reading private key
    auto f = fopen("./files/key.pem", "rb");
    if (!f)
    {
        printf("Where is private key?!\n");
        return -1;
    }

    auto rsa_ctx = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!rsa_ctx)
        return -2;

    len = RSA_size(rsa_ctx);
    unsigned char signature[len];

    {/* Code in this block should create a CertificateVerify message with rsa_pss_rsae_sha256 signature,
        but I cant figure out how to do it right... It is 512 bytes with provided private key */
        int res = RSA_sign(NID_rsassaPss, sign_data, digest_size, signature, &len, rsa_ctx);
        RSA_free(rsa_ctx);
        if (!res)
        {
            printf("RSA error %lu\n", ERR_get_error());
            return res;
        }
    }

    printf("Result: ");
    hex_dump(signature, len > 32 ? 32 : len, 32, 0);

    // check the reference made by openssl s_server application
    unsigned char* reference = NULL;
    auto ref_size = file_get_contents("./files/CertificateVerify", &reference);
    if (!reference)
        printf("Can't load refference file!\n");
    else
    {
        if (ref_size > 8)
        ref_size -= 8;

        printf("Refference: ");
        hex_dump(reference + 8, ref_size > 32 ? 32 : ref_size, 32, 0);
        printf("\n%s", equal(32, signature, reference + 8) ? "THIS IS IT! FINALLY!\n" : "THIS IS SHIT! REDO!\n");
        free(reference);
    }

    return 0;
}
