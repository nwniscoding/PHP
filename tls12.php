<?php

use nwniscoding\IO\BufferReader;
use nwniscoding\TLS\Ciphers\CipherInfo;
use nwniscoding\TLS\Ciphers\CipherRegistry;
use nwniscoding\TLS\Enums\CipherSuite;
use nwniscoding\TLS\Enums\SignatureAlgorithm;
use nwniscoding\TLS\Enums\SupportedGroup;
use nwniscoding\TLS\Enums\Version;
use nwniscoding\TLS\Extensions\EncryptThenMAC;
use nwniscoding\TLS\Sessions\Session;
use nwniscoding\TLS\TLSContext;

spl_autoload_register();

CipherRegistry::registerCipher(CipherSuite::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256, new CipherInfo('PSK', 'PSK', 'ChaCha20-Poly1305', 'SHA256'));
CipherRegistry::registerCipher(CipherSuite::TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256, new CipherInfo('ECDHE', 'PSK', 'ChaCha20-Poly1305', 'SHA256'));
CipherRegistry::registerCipher(CipherSuite::TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256, new CipherInfo('RSA', 'PSK', 'ChaCha20-Poly1305', 'SHA256'));
CipherRegistry::registerCipher(CipherSuite::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256, new CipherInfo('DHE', 'PSK', 'ChaCha20-Poly1305', 'SHA256'));
CipherRegistry::registerCipher(CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, new CipherInfo('DHE', 'RSA', 'AES-256-CBC', 'SHA256'));
CipherRegistry::registerCipher(CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256, new CipherInfo('RSA', null, 'AES-256-CBC', 'SHA256'));
CipherRegistry::registerCipher(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, new CipherInfo('ECDHE', 'ECDSA', 'AES-128-CBC', 'SHA256'));
CipherRegistry::registerCipher(CipherSuite::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256, new CipherInfo('ECDH', 'ECDSA', 'AES-128-CBC', 'SHA256'));

$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_connect($socket, 'localhost', 9000);

$context = new TLSContext(Version::TLS_12);
$session = $context->createClientSession($socket, 'nwniscoding');
$context->addGroup(...SupportedGroup::cases());
$context->addSignature(...SignatureAlgorithm::cases());

// Configs
$context->setPSKIdentity('nwniscoding', hex2bin('1a2b3c4d5e6f7081'));
$context->addCipherSuite(
  CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
  // CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
  // CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256,
  // PSK
  // CipherSuite::TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,
  // CipherSuite::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
  // CipherSuite::TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,  
  // CipherSuite::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
);

$session->negotiate();
$session->sendData("Hello, TLS 1.2!\r\n");
$session->sendData("Hello, TLS 1.2!\r\n");