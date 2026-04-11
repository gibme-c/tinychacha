// RFC 8439 ChaCha20 test vectors

struct ChaCha20Vector
{
    const char *name;
    const char *key;
    const char *nonce;
    uint32_t counter;
    const char *plaintext;
    const char *ciphertext;
};

// RFC 8439 §2.4.2 — ChaCha20 Encryption
static const ChaCha20Vector chacha20_encryption_vectors[] = {
    {
        "RFC 8439 §2.4.2 — Sunscreen",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "000000000000004a00000000",
        1,
        "4c616469657320616e642047656e746c"
        "656d656e206f662074686520636c6173"
        "73206f66202739393a20496620492063"
        "6f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220"
        "746865206675747572652c2073756e73"
        "637265656e20776f756c642062652069"
        "742e",
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42"
        "874d",
    },
};

// Keystream test vectors — plaintext is all zeros, so ciphertext = keystream
struct ChaCha20KeystreamVector
{
    const char *name;
    const char *key;
    const char *nonce;
    uint32_t counter;
    const char *keystream; // 64 bytes
};

// RFC 8439 §2.3.2 + Appendix A.1
static const ChaCha20KeystreamVector chacha20_keystream_vectors[] = {
    {
        "RFC 8439 §2.3.2 — Block function test",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "000000090000004a00000000",
        1,
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e",
    },
    {
        "RFC 8439 A.1 #1 — all zeros",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        0,
        "76b8e0ada0f13d90405d6ae55386bd28"
        "bdd219b8a08ded1aa836efcc8b770dc7"
        "da41597c5157488d7724e03fb8d84a37"
        "6a43b8f41518a11cc387b669b2ee6586",
    },
    {
        "RFC 8439 A.1 #2 — counter=1",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        1,
        "9f07e7be5551387a98ba977c732d080d"
        "cb0f29a048e3656912c6533e32ee7aed"
        "29b721769ce64e43d57133b074d839d5"
        "31ed1f28510afb45ace10a1f4b794d6f",
    },
    {
        "RFC 8439 A.1 #3 — key bit 256 set",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "000000000000000000000000",
        1,
        "3aeb5224ecf849929b9d828db1ced4dd"
        "832025e8018b8160b82284f3c949aa5a"
        "8eca00bbb4a73bdad192b5c42f73f2fd"
        "4e273644c8b36125a64addeb006c13a0",
    },
    {
        "RFC 8439 A.1 #4 — key byte 0xff at pos 1",
        "00ff000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        2,
        "72d54dfbf12ec44b362692df94137f32"
        "8fea8da73990265ec1bbbea1ae9af0ca"
        "13b25aa26cb4a648cb9b9d1be65b2c09"
        "24a66c54d545ec1b7374f4872e99f096",
    },
    {
        "RFC 8439 A.1 #5 — nonce=2",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000002",
        0,
        "c2c64d378cd536374ae204b9ef933fcd"
        "1a8b2288b3dfa49672ab765b54ee27c7"
        "8a970e0e955c14f3a88e741b97c286f7"
        "5f8fc299e8148362fa198a39531bed6d",
    },
};
