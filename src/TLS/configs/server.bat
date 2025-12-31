@echo off
openssl s_server ^
 -accept 9000 ^
 -cert ec.crt ^
 -key ec.key ^
 -cert rsa.crt ^
 -key rsa.key ^
 -psk 1a2b3c4d5e6f7081 ^
 -psk_identity myidentity ^
 -msg ^
 -state ^
 -debug
pause
