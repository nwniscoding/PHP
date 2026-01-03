@echo off
openssl s_server ^
 -accept 9000 ^
 -cert keys/ec.crt ^
 -key keys/ec.key ^
 -cert keys/rsa.crt ^
 -key keys/rsa.key ^
 -psk 1a2b3c4d5e6f7081 ^
 -psk_identity myidentity ^
 -msg ^
 -state ^
 -debug
pause
