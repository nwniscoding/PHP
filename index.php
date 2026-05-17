<?php
use nwniscoding\IO\BufferReader;
use nwniscoding\TLS\Enums\SignatureAlgorithm;
use nwniscoding\TLS\Enums\SupportedGroup;
use nwniscoding\TLS\Extensions\KeyShare;
use nwniscoding\TLS\Extensions\SupportedVersion;
use nwniscoding\TLS\Handshakes\ClientHello;
use nwniscoding\TLS\KeyShareEntry;

spl_autoload_register();

use nwniscoding\TLS\Ciphers\CipherInfo;
use nwniscoding\TLS\Ciphers\CipherRegistry;
use nwniscoding\TLS\Enums\CipherSuite;
use nwniscoding\TLS\Enums\Version;
use nwniscoding\TLS\TLSContext;

CipherRegistry::registerCipher(CipherSuite::TLS_AES_128_GCM_SHA256, new CipherInfo('ECDHE', null, 'AES-128-GCM', 'SHA256'));
$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_connect($socket, 'localhost', 9000);

$context = new TLSContext(Version::TLS_13);
$context->addGroup(SupportedGroup::X25519);
$context->addSignature(...SignatureAlgorithm::cases());
$context->addCipherSuite(CipherSuite::TLS_AES_128_GCM_SHA256);

$session = $context->createClientSession($socket, 'nwniscoding');

$session->negotiate([
  new SupportedVersion([Version::TLS_13, Version::TLS_12]),
  new KeyShare([
    new KeyShareEntry(SupportedGroup::X25519),
  ])
]);

// $client = [
//   'public' => openssl_get_publickey("file://C:\\Users\\nwnis\\Documents\\PHP\\client-ephemeral-public.key"),
//   'private' => openssl_get_privatekey("file://C:\\Users\\nwnis\\Documents\\PHP\\client-ephemeral-private.key"),
// ];

// $server = [
//   'public' => openssl_get_publickey("file://C:\\Users\\nwnis\\Documents\\PHP\\server-ephemeral-public.key"),
//   'private' => openssl_get_privatekey("file://C:\\Users\\nwnis\\Documents\\PHP\\server-ephemeral-private.key"),
// ];

// $clientHello = <<<HEX
// 01 00 00 f4 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 08 13 02 13 03 13 01 00 ff 01 00 00 a3 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0b 00 04 03 00 01 02 00 0a 00 16 00 14 00 1d 00 17 00 1e 00 19 00 18 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 16 00 00 00 17 00 00 00 0d 00 1e 00 1c 04 03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08 05 08 06 04 01 05 01 06 01 00 2b 00 03 02 03 04 00 2d 00 02 01 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54
// HEX;

// $clientHello = hex2bin(preg_replace('/\s+/', '', $clientHello));

// $serverHello = <<<HEX
// 02 00 00 76 03 03 70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 13 02 00 00 2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 20 9f d7 ad 6d cf f4 29 8d d3 f9 6d 5b 1b 2a f9 10 a0 53 5b 14 88 d7 f8 fa bb 34 9a 98 28 80 b6 15
// HEX;

// $serverHello = hex2bin(preg_replace('/\s+/', '', $serverHello));


// $hash = 'sha384';
// $hashLength = 48;

// # verified to be correct 
// function hkdf_extract(string $hash, int $hashLength, string $salt, string $ikm) : string{
//   if($salt === '') $salt = str_repeat("\0", $hashLength);

//   return hash_hmac($hash, $ikm, $salt, true);
// }

// function hkdf_expand(string $hash, string $prk, string $info, int $length): string
// {
//     $hashLen = strlen(hash($hash, '', true));
//     $n = (int) ceil($length / $hashLen);

//     $okm = '';
//     $t = '';

//     for ($i = 1; $i <= $n; $i++) {
//         // T(i) = HMAC(PRK, T(i-1) || info || i)
//         $t = hash_hmac($hash, $t . $info . chr($i), $prk, true);
//         $okm .= $t;
//     }

//     return substr($okm, 0, $length);
// }

// function hkdf_expand_label(
//     string $hash,
//     string $secret,   // PRK
//     string $label,    // MUST include "tls13 " if you're not adding it here
//     string $context,
//     int $length
// ): string {

//     // Build HkdfLabel struct
//     $info =
//         pack('n', $length) .
//         chr(strlen($label)) . $label .
//         chr(strlen($context)) . $context;

//       var_dump(bin2hex($info));

//     return hkdf_expand($hash, $secret, $info, $length);
// }


// $helloHash = hash($hash, $clientHello.$serverHello, true);
// $sharedSecret = openssl_pkey_derive($client['public'], $server['private']);
// $zeroKey = str_repeat("\0", $hashLength);
// $earlySecret = hkdf_extract($hash, $hashLength, '', $zeroKey);
// $emptyHash = hash($hash, '', true);
// // var_dump((KeySchedule::expand($earlySecret, KeySchedule::TLS_13_DERIVED_LABEL, $emptyHash, 48, $cipherInfo)));
// $derivedSecret = hkdf_expand_label($hash, $earlySecret, 'tls13 derived', $emptyHash, $hashLength);
// $handshakeSecret = hkdf_extract($hash, $hashLength, $derivedSecret, $sharedSecret);
// $serverHandshakeTrafficSecret = hkdf_expand_label($hash, $handshakeSecret, 'tls13 s hs traffic', $helloHash, $hashLength);
// $clientHandshakeTrafficSecret = hkdf_expand_label($hash, $handshakeSecret, 'tls13 c hs traffic', $helloHash, $hashLength);
// $serverKey = hkdf_expand_label($hash, $serverHandshakeTrafficSecret, 'tls13 key', '', 32);
// $serverIV = hkdf_expand_label($hash, $serverHandshakeTrafficSecret, 'tls13 iv', '', 12);
// $clientKey = hkdf_expand_label($hash, $clientHandshakeTrafficSecret, 'tls13 key', '', 32);
// $clientIV = hkdf_expand_label($hash, $clientHandshakeTrafficSecret, 'tls13 iv', '', 12);

// echo "hello_hash=".bin2hex($helloHash)."\n";
// echo "shared_secret=".bin2hex($sharedSecret)."\n";
// echo "zero_key=".bin2hex($zeroKey)."\n";
// echo "early_secret=".bin2hex($earlySecret) ."\n";
// echo "empty_hash=".bin2hex($emptyHash) ."\n";
// echo "derived_secret=".bin2hex($derivedSecret) ."\n";
// echo "hssec: ".bin2hex($handshakeSecret) ."\n";
// echo "ssec: ".bin2hex($serverHandshakeTrafficSecret) ."\n";
// echo "csec: ".bin2hex($clientHandshakeTrafficSecret) ."\n";
// echo "skey: ".bin2hex($serverKey) ."\n";
// echo "siv: ".bin2hex($serverIV) ."\n";
// echo "ckey: ".bin2hex($clientKey) ."\n";
// echo "civ: ".bin2hex($clientIV) ."\n";

// $derivedSecret = hkdf_expand_label($hash, $earlySecret, 'tls13 derived', $emptyHash, $hashLength);
// $cipherInfo = new CipherInfo('AEAD', null, 'AES-128-GCM', 'SHA384');
