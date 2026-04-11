// RFC 8439 AEAD test vectors

struct AeadVector
{
    const char *name;
    const char *key;
    const char *nonce;
    const char *aad;
    const char *plaintext;
    const char *ciphertext;
    const char *tag;
};

// RFC 8439 §2.8.2 — AEAD Construction
static const AeadVector aead_rfc_vectors[] = {
    {
        "RFC 8439 §2.8.2 — AEAD test vector",
        // Key
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        // Nonce
        "070000004041424344454647",
        // AAD
        "50515253c0c1c2c3c4c5c6c7",
        // Plaintext: "Ladies and Gentlemen of the class of '99: If I could..."
        "4c616469657320616e642047656e746c"
        "656d656e206f662074686520636c6173"
        "73206f66202739393a20496620492063"
        "6f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220"
        "746865206675747572652c2073756e73"
        "637265656e20776f756c642062652069"
        "742e",
        // Ciphertext
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116",
        // Tag
        "1ae10b594f09e26a7e902ecbd0600691",
    },
};


// RFC 8439 §2.6.2 — Poly1305 Key Generation test vector
struct PolyKeyGenVector
{
    const char *name;
    const char *key;
    const char *nonce;
    const char *expected_poly_key; // 32 bytes
};

static const PolyKeyGenVector poly_key_gen_vectors[] = {
    {
        "RFC 8439 §2.6.2 — Poly1305 key generation",
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        "000000000001020304050607",
        "8ad5a08b905f81cc815040274ab29471"
        "a833b637e3fd0da508dbb8e2fdd1a646",
    },
};
