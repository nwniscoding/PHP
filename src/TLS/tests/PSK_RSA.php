<?php

use TLS\Context;
use TLS\Enums\CipherSuite;
use TLS\Enums\HandshakeType;
use TLS\Enums\RecordType;
use TLS\Enums\SignatureAlgorithm;
use TLS\Enums\SupportedGroup;
use TLS\Enums\Version;
use TLS\Extensions\SignatureAlgorithms;
use TLS\Extensions\SupportedGroups;
use TLS\Handshakes\Certificate;
use TLS\Handshakes\ClientHello;
use TLS\Handshakes\ClientKeyExchange;
use TLS\Handshakes\Finished;
use TLS\Handshakes\ServerHello;
use TLS\Params\RSAParam;
use TLS\Record;
use TLS\Utils\Crypto;
spl_autoload_register('spl_autoload');

/**
 * This example uses RSA with PSK cipher suite to connect to a TLS server.
 */

$host = 'localhost';
$port = 9000;
$psk = hex2bin('1a2b3c4d5e6f7081');
$psk_identity = 'myidentity';
$socket = null;
$version = Version::TLS_12;

$context = new Context($version);

$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_connect($socket, $host, $port);

$client_hello = new ClientHello($context);
$client_hello
->setVersion($version)
->addCipherSuite(CipherSuite::TLS_RSA_PSK_WITH_AES_128_CBC_SHA256)
->addExtension(new SignatureAlgorithms(
  SignatureAlgorithm::RSA_PKCS1_SHA256,
  SignatureAlgorithm::RSA_PSS_PSS_SHA256
))
->addExtension(new SupportedGroups(
  SupportedGroup::SECP256R1
))
;

$context->addHandshake($client_hello);
socket_write(
  $socket, 
  Record::handshake(Version::TLS_12, $client_hello)
);

foreach(Record::parse(socket_read($socket, 8192), $context) as $record){
  if($record->getType() === RecordType::HANDSHAKE){
    $payload = $record->getPayload();
    $context->addHandshake($payload);
  }
}

/**
 * @var ServerHello
 */
$server_hello = $context->getHandshake(HandshakeType::SERVER_HELLO);
/**
 * @var Certificate
 */
$certificate = $context->getHandshake(HandshakeType::CERTIFICATE);
$cipher = $server_hello->getCipherSuite();

$generated_secret = openssl_random_pseudo_bytes(48);
$generated_secret[0] = chr(0x3);
$generated_secret[1] = chr(0x3);

openssl_public_encrypt(
  $generated_secret, 
  $encrypted_secret, 
  $certificate->getCertificate(0),
  OPENSSL_PKCS1_PADDING
);

$premaster_secret = pack(
  'na*na*',
  strlen($generated_secret),
  $generated_secret,
  strlen($psk),
  $psk
);

$client_key_exchange = new ClientKeyExchange($context);
$client_key_exchange
->setPSKIdentity($psk_identity)
->setParam(new RSAParam($encrypted_secret))
;

$context->addHandshake($client_key_exchange);

socket_write(
  $socket,
  Record::handshake(Version::TLS_12, $client_key_exchange).
  Record::changeCipherSpec(Version::TLS_12)
);

$master_secret = Crypto::PRF(
  $cipher,
  $premaster_secret,
  'master secret',
  $client_hello->getRandom() . $server_hello->getRandom(),
  48
);

$key_block = Crypto::PRF(
  $cipher,
  $master_secret,
  'key expansion',
  $server_hello->getRandom() . $client_hello->getRandom(),
  128
);

$client = [
  'mac' => substr($key_block, 0, 32),
  'key' => substr($key_block, 64, 16),
  'iv' => substr($key_block, 96, 16)
];

$finished = new Finished($context);
$finished->createMAC(
  $cipher,
  $master_secret,
  'client',
   $context->getHandshakes()
);

$mac = Crypto::HMACRecord(
  $cipher,
  0,
  $client['mac'],
  Record::handshake(Version::TLS_12, $finished)
);
$plaintext = $finished . $mac;
$plaintext = Crypto::pad($plaintext, 16);
$iv = $client['iv'];

$ciphertext = openssl_encrypt(
  $plaintext,
  'AES-128-CBC',
  $client['key'],
  OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
  $iv
);

socket_write(
  $socket,
  Record::handshake(Version::TLS_12, $iv . $ciphertext)
);

socket_read($socket, 8192);

socket

sleep(2);