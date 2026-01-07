<?php

use TLS\Enums\CipherSuite;
use TLS\Enums\HandshakeType;
use TLS\Enums\RecordType;
use TLS\Enums\SignatureAlgorithm;
use TLS\Enums\SupportedGroup;
use TLS\Enums\Version;
use TLS\Extensions\SignatureAlgorithms;
use TLS\Extensions\SupportedGroups;
use TLS\Handshakes\ClientHello;
use TLS\Record;

spl_autoload_register('spl_autoload');

$handshakes = [];
$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);

socket_connect($socket, 'localhost', 9000);

$client_hello = new ClientHello;
$client_hello
->setVersion(Version::TLS_12)
->addCipherSuite(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256)
->addExtension(new SignatureAlgorithms(
  SignatureAlgorithm::ECDSA_SECP256R1_SHA256,
))
->addExtension(
  new SupportedGroups(
    SupportedGroup::SECP256R1,
  )
)
; // Disable this line to test without ETM

$handshakes[] = $client_hello;

socket_write(
  $socket, 
  Record::handshake(Version::TLS_12, $client_hello)
);

foreach(Record::parse(socket_read($socket, 8192)) as $record){
  if($record->getType() === RecordType::HANDSHAKE){
    $handshakes[] = $handshake = $record->getPayload();

    $handshake_type = $handshake->getType();

    switch($handshake_type){
      case HandshakeType::SERVER_HELLO:
        $server_hello = $handshake;
        break;
      case HandshakeType::SERVER_KEY_EXCHANGE:
        $server_key_exchange = $handshake;
        break;
      case HandshakeType::CERTIFICATE:
        $certificate = $handshake;
        break;
    }
  }
}

// $client_key_exchange = new ClientKeyExchange();
// $client_key_exchange
// ->setPSKIdentity($psk_identity);

// $server_hello = $handshakes[1]; 
// $handshakes[] = $client_key_exchange;

$client_random = $client_hello->getRandom();
$server_random = $server_hello->getRandom();

// socket_write(
//   $socket, 
//   Record::handshake(Version::TLS_12, $client_key_exchange).
//   Record::changeCipherSpec(Version::TLS_12)
// );

// $master_secret = Crypto::PRF(
//   $cipher,
//   $premaster_secret,
//   'master secret',
//   48
// );

// $client = Crypto::generateKey(
//   $cipher,
//   $master_secret,
//   $client_random,
//   $server_random
// )['client'];

// $iv = openssl_random_pseudo_bytes(16);
// $verify_data = Crypto::PRF(
//   $cipher,
//   $master_secret,
//   'client finished',
//   hash('sha256', join('', $handshakes), true),
//   12
// );

// $finished = new Finished();
// $finished->createMAC($cipher, $master_secret, 'client', $handshakes);

// if($client_hello->hasExtension(ExtensionType::ENCRYPT_THEN_MAC)){
//   $plaintext = Crypto::pad($finished, 16);

//   $ciphertext = openssl_encrypt(
//     $plaintext,
//     'AES-128-CBC',
//     $client['key'],
//     OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
//     $iv
//   );

//   $mac = Crypto::HMACRecord(
//     $cipher, 
//     0, 
//     $client['mac'], 
//     Record::handshake(Version::TLS_12, $iv.$ciphertext)
//   );

//   $ciphertext .= $mac;
// }
// else{
//   $mac = Crypto::HMACRecord(
//     $cipher, 
//     0, 
//     $client['mac'], 
//     Record::handshake(Version::TLS_12, $finished)
//   );
  
//   $plaintext = $finished . $mac;
//   $plaintext = Crypto::pad($plaintext, 16);
  
//   $ciphertext = openssl_encrypt(
//     $plaintext,
//     'AES-128-CBC',
//     $client['key'],
//     OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
//     $iv
//   );
// }

// socket_write(
//   $socket,
//   Record::handshake(Version::TLS_12, $iv.$ciphertext)
// );

// sleep(5);

// socket_write($socket, 'test');