<?php

use TLS\Enums\CipherSuite;
use TLS\Enums\RecordType;
use TLS\Enums\Version;
use TLS\Handshakes\ClientHello;
// /**
//  * TLS Client Example
//  * 
//  * The following ciphers are supported by the openssl server:
//  * ECDHE-ECDSA-AES256-GCM-SHA384  TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AESGCM(256)            Mac=AEAD
//  * ECDHE-RSA-AES256-GCM-SHA384    TLSv1.2 Kx=ECDH     Au=RSA   Enc=AESGCM(256)            Mac=AEAD
//  * DHE-RSA-AES256-GCM-SHA384      TLSv1.2 Kx=DH       Au=RSA   Enc=AESGCM(256)            Mac=AEAD
//  * ECDHE-ECDSA-CHACHA20-POLY1305  TLSv1.2 Kx=ECDH     Au=ECDSA Enc=CHACHA20/POLY1305(256) Mac=AEAD
//  * ECDHE-RSA-CHACHA20-POLY1305    TLSv1.2 Kx=ECDH     Au=RSA   Enc=CHACHA20/POLY1305(256) Mac=AEAD
//  * DHE-RSA-CHACHA20-POLY1305      TLSv1.2 Kx=DH       Au=RSA   Enc=CHACHA20/POLY1305(256) Mac=AEAD
//  * ECDHE-ECDSA-AES128-GCM-SHA256  TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AESGCM(128)            Mac=AEAD
//  * ECDHE-RSA-AES128-GCM-SHA256    TLSv1.2 Kx=ECDH     Au=RSA   Enc=AESGCM(128)            Mac=AEAD
//  * DHE-RSA-AES128-GCM-SHA256      TLSv1.2 Kx=DH       Au=RSA   Enc=AESGCM(128)            Mac=AEAD
//  * ECDHE-ECDSA-AES256-SHA384      TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AES(256)               Mac=SHA384
//  * ECDHE-RSA-AES256-SHA384        TLSv1.2 Kx=ECDH     Au=RSA   Enc=AES(256)               Mac=SHA384
//  * DHE-RSA-AES256-SHA256          TLSv1.2 Kx=DH       Au=RSA   Enc=AES(256)               Mac=SHA256
//  * ECDHE-ECDSA-AES128-SHA256      TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AES(128)               Mac=SHA256
//  * ECDHE-RSA-AES128-SHA256        TLSv1.2 Kx=ECDH     Au=RSA   Enc=AES(128)               Mac=SHA256
//  * DHE-RSA-AES128-SHA256          TLSv1.2 Kx=DH       Au=RSA   Enc=AES(128)               Mac=SHA256
//  * RSA-PSK-AES256-GCM-SHA384      TLSv1.2 Kx=RSAPSK   Au=RSA   Enc=AESGCM(256)            Mac=AEAD
//  * DHE-PSK-AES256-GCM-SHA384      TLSv1.2 Kx=DHEPSK   Au=PSK   Enc=AESGCM(256)            Mac=AEAD
//  * RSA-PSK-CHACHA20-POLY1305      TLSv1.2 Kx=RSAPSK   Au=RSA   Enc=CHACHA20/POLY1305(256) Mac=AEAD
//  * DHE-PSK-CHACHA20-POLY1305      TLSv1.2 Kx=DHEPSK   Au=PSK   Enc=CHACHA20/POLY1305(256) Mac=AEAD
//  * ECDHE-PSK-CHACHA20-POLY1305    TLSv1.2 Kx=ECDHEPSK Au=PSK   Enc=CHACHA20/POLY1305(256) Mac=AEAD
//  * AES256-GCM-SHA384              TLSv1.2 Kx=RSA      Au=RSA   Enc=AESGCM(256)            Mac=AEAD
//  * PSK-AES256-GCM-SHA384          TLSv1.2 Kx=PSK      Au=PSK   Enc=AESGCM(256)            Mac=AEAD
//  * PSK-CHACHA20-POLY1305          TLSv1.2 Kx=PSK      Au=PSK   Enc=CHACHA20/POLY1305(256) Mac=AEAD
//  * RSA-PSK-AES128-GCM-SHA256      TLSv1.2 Kx=RSAPSK   Au=RSA   Enc=AESGCM(128)            Mac=AEAD
//  * DHE-PSK-AES128-GCM-SHA256      TLSv1.2 Kx=DHEPSK   Au=PSK   Enc=AESGCM(128)            Mac=AEAD
//  * AES128-GCM-SHA256              TLSv1.2 Kx=RSA      Au=RSA   Enc=AESGCM(128)            Mac=AEAD
//  * PSK-AES128-GCM-SHA256          TLSv1.2 Kx=PSK      Au=PSK   Enc=AESGCM(128)            Mac=AEAD
//  * AES256-SHA256                  TLSv1.2 Kx=RSA      Au=RSA   Enc=AES(256)               Mac=SHA256
//  * AES128-SHA256                  TLSv1.2 Kx=RSA      Au=RSA   Enc=AES(128)               Mac=SHA256
//  */

// use TLS\Config;
// use TLS\Context;
// use TLS\Enums\CipherSuite;
// use TLS\Enums\RecordType;
// use TLS\Enums\SignatureAlgorithm;
// use TLS\Enums\SupportedGroup;
// use TLS\Enums\Version;
// use TLS\Extensions\RenegotiationInfo;
// use TLS\Extensions\SignatureAlgorithms;
// use TLS\Extensions\SupportedGroups;
// use TLS\Handshakes\ClientHello;
// use TLS\Handshakes\ClientKeyExchange;
// use TLS\Handshakes\Finished;
// use TLS\Handshakes\ServerHello;
// use TLS\Record;
// use TLS\Utils\Crypto;

// spl_autoload_register('spl_autoload');

// $config = [
//   'host' => 'localhost',
//   'port' => 9000,
//   'version' => Version::TLS_12,
//   'identity' => 'my_identity',
//   'psk' => hex2bin('1a2b3c4d5e6f7081')
// ];

// // Refer above for supported cipher suites
// $cipher = CipherSuite::TLS_PSK_WITH_AES_128_CBC_SHA256;
// // $cipher = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;

// // Create TCP socket and connect to server
// $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);

// if(!socket_connect($socket, $config['host'], $config['port'])){
//   die("Unable to connect to $config[host]:$config[port]\n");
// }

// echo "Connected to the server\n";

// $handshakes = [];
// $client_hello = new ClientHello;

// $handshakes[] = $client_hello;

// $client_hello
// ->setVersion(Version::TLS_12)
// ->addCipherSuite($cipher)
// ->addExtension(new RenegotiationInfo())
// ->addExtension(new SignatureAlgorithms(
//   SignatureAlgorithm::ECDSA_SECP521R1_SHA512
// ))
// ->addExtension(new SupportedGroups(
//   SupportedGroup::SECP256R1
// ));

// if(socket_write($socket, Record::handshake(Version::TLS_12, $client_hello))){
//   echo "Handshake {$client_hello->getType()->name} sent\n";
// }
// else{
//   echo "Failed to send ClientHello\n";
//   return;
// }

// foreach(Record::parse(socket_read($socket, 8192)) as $record){
//   $payload = $record->getPayload();

//   if($record->getType() === RecordType::HANDSHAKE){
//     $handshakes[] = $payload;

//     if($payload instanceof ServerHello) $server_hello = $payload;
        
//     echo "Handshake {$payload->getType()->name} received\n";
//   }
// }

// $metadata = $server_hello->getCipherSuite()->metadata();

// $client_key_exchange = new ClientKeyExchange();

// if($metadata['authentication'] === 'PSK'){
//   echo "Using PSK authentication\n";

//   $premaster_secret = pack(
//     'na*na*',
//     strlen($config['psk']),
//     $config['psk'],
//     strlen($config['psk']),
//     $config['psk']
//   );

//   $master_secret = Crypto::PRF(
//     $server_hello->getCipherSuite(), 
//     $premaster_secret,
//     'master secret',
//     $client_hello->getRandom() . $server_hello->getRandom(),
//     48
//   );

//   $keys = Crypto::generateKey(
//     $server_hello->getCipherSuite(),
//     $master_secret,
//     $client_hello->getRandom(),
//     $server_hello->getRandom()
//   );

//   $client_key_exchange->setPSKIdentity($config['identity']);
//   $handshakes[] = $client_key_exchange;

//   $finished = new Finished();
//   $finished->createMAC(
//     $server_hello->getCipherSuite(),
//     $master_secret,
//     'client',
//     $handshakes
//   );

//   $mac_record = Crypto::HMACRecord(
//     $server_hello->getCipherSuite(),
//     0,
//     $keys['client']['mac'],
//     Record::handshake(Version::TLS_12, $finished)
//   );

//   $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($metadata['encryption']));

//   var_dump($mac_record);

//   $plaintext = $finished . $mac_record;
//   $plaintext = Crypto::pad($plaintext, 16);

//   var_dump(bin2hex($plaintext));

//   $ciphertext = openssl_encrypt(
//     Crypto::pad($plaintext, 16),
//     'aes-128-cbc',
//     $keys['client']['key'],
//     OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
//     $iv
//   );

//   socket_write(
//     $socket, 
//     Record::handshake(
//     Version::TLS_12,
//     $client_key_exchange
//     ).
//     Record::changeCipherSpec(Version::TLS_12).
//     Record::handshake(Version::TLS_12, $iv . $ciphertext)
//   );


// }
// else{
//   echo "Using {$metadata['authentication']} authentication\n";
// }

// // var_dump($server_hello->getCipherSuite());

function handshake_record(Version $version, string $data){
}

$cipher = CipherSuite::TLS_PSK_WITH_AES_128_CBC_SHA256;
$psk = hex2bin('1a2b3c4d5e6f7081');
$psk_identity = 'my_identity';
$psk_len = strlen($psk);

$premaster_secret = pack(
  'na*na*',
  $psk_len,
  str_repeat("\0", $psk_len),
  $psk_len,
  $psk
);

var_dump(pack('n', Version::TLS12));