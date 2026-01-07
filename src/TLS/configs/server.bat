@echo off
@REM  -cert keys/ec.crt ^
@REM  -key keys/ec.key ^

openssl s_server ^
 -accept 9000 ^
 -cert keys/rsa.crt ^
 -key keys/rsa.key ^
 -psk 1a2b3c4d5e6f7081 ^
 -psk_identity myidentity ^
 -msg ^
 -state ^
 -debug
pause
