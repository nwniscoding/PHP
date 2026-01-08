openssl s_client ^
-connect localhost:9000 ^
-psk 1a2b3c4d5e6f7081 ^
-psk_identity myidentity ^
-tls1_2 ^
-no_ticket ^
-msg ^
-state ^
-debug ^
-cipher TLS_RSA_PSK_WITH_AES_128_CBC_SHA256
