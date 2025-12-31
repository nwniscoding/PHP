<?php

use TLS\Client;
use TLS\Config;
use TLS\Enums\CipherSuite;
use TLS\Enums\SignatureAlgorithm;
use TLS\Enums\SupportedGroup;
use TLS\Enums\Version;
use TLS\Extensions\RenegotiationInfo;
use TLS\Extensions\SignatureAlgorithms;
use TLS\Extensions\SupportedGroups;
spl_autoload_register('spl_autoload');

$config = new Config(Version::TLS_12);
$client = new Client("localhost", 9000, $config);

$config->addCipherSuite(CipherSuite::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256);
$config->addCipherSuite(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
$config->addCipherSuite(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
$config->addCipherSuite(CipherSuite::TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256);
$config->addExtension(new RenegotiationInfo());
$config->addExtension(new SignatureAlgorithms(
  SignatureAlgorithm::RSA_PKCS1_SHA256, 
  SignatureAlgorithm::ECDSA_SECP256R1_SHA256,
  SignatureAlgorithm::RSA_PKCS1_SHA384, 
  SignatureAlgorithm::ECDSA_SECP384R1_SHA384
));
$config->addExtension(new SupportedGroups(
  SupportedGroup::SECP256R1,
  SupportedGroup::SECP384R1
));

$client->connect();