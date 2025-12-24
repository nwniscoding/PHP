<?php

use nwniscoding\TLS\Handshakes\ClientHello;
require_once 'autoload.php';
require_once 'util.php';

$client_hello = <<<HEX
01 00 00 66 03 03 67 71 59 a0 e0 49 35 17 1e 51
f1 be f0 a4 78 a7 34 f1 82 13 97 63 15 11 0f 29
8a 33 00 86 fb ea 00 00 02 00 ae 01 00 00 3b ff
01 00 01 00 00 16 00 00 00 17 00 00 00 0d 00 2a
00 28 04 03 05 03 06 03 08 07 08 08 08 09 08 0a
08 0b 08 04 08 05 08 06 04 01 05 01 06 01 03 03
03 01 03 02 04 02 05 02 06 02
HEX;

$server_hello = <<<HEX
02 00 00 55 03 03 65 1c 36 1e 5a 92 86 37 96 ec
c6 4a 9e 6b 7f 85 07 12 90 a8 66 17 58 58 44 4f
57 4e 47 52 44 01 20 78 41 7e 07 b3 9f 4d 01 33
73 59 a4 ff d6 58 54 57 12 47 e0 3b 6e 58 5a 67
8d da 2a d6 a3 ed c9 00 ae 00 00 0d ff 01 00 01
00 00 16 00 00 00 17 00 00
HEX;

$server_hello_done = <<<HEX
0e 00 00 00
HEX;

$client_key_exchange = <<<HEX
10 00 00 0c 00 0a 6d 79 69 64 65 6e 74 69 74 79
HEX;

$encrypted_handshake = <<<HEX
11 b6 79 65 29 85 38 0a b4 22 e5 11 d7 e6 e8 9e
b7 e7 fe bd fd 6b 36 6f ec 3a 66 a9 91 04 77 13
9c e1 83 af 4f f9 e0 9f 2e 12 f7 e0 d5 31 39 88
b4 ad ef 6e d1 a7 6b 66 13 5e 4f 37 e3 a6 b5 0e
81 ac 2e 17 c1 b0 83 71 bf 79 a3 39 44 bb dd 1d
HEX;

$psk = unhex('1a2b3c4d5e6f7081');
$pre_master_secret = pack('n', strlen($psk)) . str_repeat("\0", strlen($psk)) . pack('n', strlen($psk)) . $psk;

$client_hello = unhex($client_hello);
$server_hello = unhex($server_hello);
$server_hello_done = unhex($server_hello_done);
$client_key_exchange = unhex($client_key_exchange);

$handshake_hash = hash(
  'sha256',
  $client_hello . 
  $server_hello . 
  $server_hello_done . $client_key_exchange,
  true
);

$master_secret = tls_prf(
  'extended master secret', 
  $pre_master_secret,
  $handshake_hash,
  48
);

echo 'Master Secret: ' . bin2hex($master_secret) . "\n";

$client_random = substr($client_hello, 6, 32);
$server_random = substr($server_hello, 6, 32);

echo "Client Random: " . bin2hex($client_random) . "\n";
echo "Server Random: " . bin2hex($server_random) . "\n";

$key_block = tls_prf(
  'key expansion',
  $master_secret,
  $server_random . $client_random,
  128
);

$client = [
  'mac' => substr($key_block, 0, 32),
  'key' => substr($key_block, 64, 16)
];

$server = [
  'mac' => substr($key_block, 32, 32),
  'key' => substr($key_block, 80, 16)
];

echo "\n";
echo "Client MAC Key: " . bin2hex($client['mac']) . "\n";
echo "Client Enc Key: " . bin2hex($client['key']) . "\n";
echo "Server MAC Key: " . bin2hex($server['mac']) . "\n";
echo "Server Enc Key: " . bin2hex($server['key']) . "\n";

$encrypted_handshake = unhex($encrypted_handshake);
$encrypted_iv = substr($encrypted_handshake, 0, 16);
$encrypted_handshake = substr($encrypted_handshake, 16);
$mac_result = substr($encrypted_handshake, -32);
$encrypted_handshake = substr($encrypted_handshake, 0, 32);

$decrypted_handshake = openssl_decrypt(
  $encrypted_handshake,
  'AES-128-CBC',
  $client['key'],
  OPENSSL_RAW_DATA,
  $encrypted_iv
);

echo "Extracted MAC: " . bin2hex($mac_result) . "\n";
echo "Encrypted Handshake: " . bin2hex($encrypted_handshake) . "\n";
echo "Encrypted IV: " . bin2hex($encrypted_iv) . "\n\n";

echo 'Decrypted Handshake: ' . bin2hex($decrypted_handshake) . "\n";
var_dump(hash_hmac(
  'sha256', 
  pack('N2', 0, 0).
  pack('C', 0x16).
  pack('n', 0x0303).
  pack('n', strlen($encrypted_handshake)).$encrypted_handshake,
  $client['mac']));
var_dump(bin2hex($mac_result));

var_dump(bin2hex($encrypted_handshake));

// $actual_mac = unhex("14 00 00 0c 70 76 e1 d1 f7 03 d8 f3 b9 7f b2 3d");
// $verify_data = tls_prf("client finished", $master_secret, $handshake_hash, 12);

// echo 'Actual MAC: ' . bin2hex($actual_mac) . "\n";
// echo "Verify Data: " . bin2hex($verify_data) . "\n";
// echo "Matches original data: " . (str_contains($decrypted_handshake, $actual_mac) ? 'Yes' : 'No') . "\n";
// echo "Matches Verify data: " . (str_contains($decrypted_handshake, $verify_data) ? 'Yes' : 'No') . "\n";



// $plaintext = substr($decrypted_handshake, 0, -32);
// $encrypted_fragment = openssl_encrypt(
//   $plaintext,
//   'AES-128-CBC',
//   $client['key'],
//   OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
//   $encrypted_iv
// );

// $seq_num = 0; // first record

// $mac_data = pack('J', $seq_num)           // 64-bit sequence number, big-endian
//           . pack('C', 0x16)               // ContentType = Handshake
//           . pack('n', 0x0303)             // TLS 1.2 version
//           . pack('n', strlen($encrypted_fragment)) // length of ciphertext
//           . $encrypted_fragment;          // ciphertext

// $record_mac = hash_hmac('sha256', $mac_data, $client['mac'], true);

// echo "Plaintext: " . bin2hex($plaintext) . "\n";
// echo "Encrypted Fragment: " . bin2hex($encrypted_fragment) . "\n";
// echo "MAC: " . bin2hex($record_mac) . "\n";

// So given that both the client and server (via openssl) displays EtM, does that mean that when I decrypt the message, it is wrong?

// Not necessarily “wrong,” but it changes how you interpret the decrypted data. Let me explain carefully.

// 1. What happens with Encrypt-then-MAC (EtM)

// In EtM, the record-layer MAC is computed over the ciphertext and appended outside the encryption.

// Decryption only happens after verifying the MAC.

// That means the last bytes of the received record are the HMAC, not part of the encrypted fragment.

// 2. What you currently did
// $decrypted_handshake = openssl_decrypt(
//   $encrypted_handshake,
//   'AES-128-CBC',
//   $client['key'],
//   OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
//   $encrypted_iv
// );


// You decrypted $encrypted_handshake without first checking the EtM HMAC.

// Result: $decrypted_handshake includes:

// Finished handshake message + padding + EtM HMAC


// The part that is the MAC at the end should not have been decrypted, because EtM expects it to be outside the encrypted fragment.

// 3. Correct EtM handling

// Split the record:

// record = IV || ciphertext || record_mac


// $encrypted_fragment = ciphertext (everything that was encrypted, including padding)

// $record_mac = last 32 bytes (HMAC-SHA256 of ciphertext + header)

// Verify the MAC first:

// $mac_data = seq_num || type || version || len(encrypted_fragment) || encrypted_fragment
// computed_mac = HMAC(mac_key, mac_data)


// Compare computed_mac with $record_mac

// If it matches → OK

// If it fails → reject record

// Decrypt ciphertext after verifying MAC:

// $plaintext = openssl_decrypt($encrypted_fragment, AES-128-CBC, key, IV)


// $plaintext now contains Finished handshake + padding

// The HMAC is not part of $plaintext because it was outside encryption

// 4. Why your decrypted handshake seems “off”

// You decrypted the whole record including the appended EtM MAC.

// That’s why the last 32 bytes look like a MAC inside the decrypted plaintext.

// In reality, the MAC is not encrypted — it should be used for verification before decryption.

// ✅ Conclusion

// The decryption itself is not wrong, but the data you passed to openssl_decrypt included the EtM MAC, which it shouldn’t.

// With EtM, the flow should be:

// 1. Extract encrypted fragment (ciphertext)
// 2. Extract record MAC
// 3. Verify MAC over ciphertext + header
// 4. Only then decrypt ciphertext


// After this, $plaintext = Finished handshake + padding, without the MAC at the end.

// If you want, I can rewrite your current snippet to handle EtM properly, splitting the record, verifying the MAC first, and then decrypting so your $plaintext no longer contains the record MAC. This will reflect the correct TLS 1.2 EtM behavior.