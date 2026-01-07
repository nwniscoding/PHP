/**
 * This example demonstrates a simple TLS client that only supports PSK cipher suites.
 * It includes the following features:
 * - Uses Encrypt-then-MAC and MAC-then-encrypt based on the server's support.
 * - Uses extended master secret if the server supports it.
 * - Establishes a secure connection to a TLS server using PSK authentication.
 */

declare(strict_types=1);

use TLS\Context;
use TLS\Crypto\AEADCipher;
use TLS\Crypto\BlockCipher;
use TLS\Enums\CipherSuite;
use TLS\Enums\ExtensionType;
use TLS\Enums\HandshakeType;
use TLS\Enums\RecordType;
use TLS\Enums\SignatureAlgorithm;
use TLS\Enums\SupportedGroup;
use TLS\Enums\Version;
use TLS\Extensions\EncryptThenMAC;
use TLS\Extensions\ExtendedMasterSecret;
use TLS\Extensions\SignatureAlgorithms;
use TLS\Extensions\SupportedGroups;
use TLS\Handshakes\Certificate;
use TLS\Handshakes\ClientHello;
use TLS\Handshakes\ClientKeyExchange;
use TLS\Handshakes\Finished;
use TLS\Handshakes\ServerHello;
use TLS\Handshakes\ServerKeyExchange;
use TLS\Params\RSAParam;
use TLS\Record;
use TLS\Utils\Crypto;

spl_autoload_register('spl_autoload');

/**
 * Configuration for the TLS client.
 */
$host = 'localhost';
$port = 9000;
$psk = hex2bin('1a2b3c4d5e6f7081');
$psk_identity = 'myidentity';
$socket = null;
$version = Version::TLS_12;
$context = new Context($version); 

// This is the default premaster secret structure
$premaster_secret = pack(
  'na*na*',
  strlen($psk),
  str_repeat("\0", strlen($psk)),
  strlen($psk),
  $psk
);

// Create and connect the socket
$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_connect($socket, $host, $port);

// Start the TLS handshake
$client_hello = new ClientHello($context);
$client_hello
->setVersion($version)
// These are PSK cipher suites we will be using to test PSK-only connection
// Test for CBC and GCM modes
->addCipherSuite(CipherSuite::TLS_PSK_WITH_AES_128_CBC_SHA256)
// ->addCipherSuite(CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256)
// Test for RSA-PSK, DHE-PSK and ECDHE-PSK key exchanges
// ->addCipherSuite(CipherSuite::TLS_RSA_PSK_WITH_AES_128_CBC_SHA256)
// ->addCipherSuite(CipherSuite::TLS_DHE_PSK_WITH_AES_128_CBC_SHA256)
// ->addCipherSuite(CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256)
// Test for Encrypt-then-MAC support
// ->addExtension(new EncryptThenMAC)
// Test for Extended Master Secret support
// ->addExtension(new ExtendedMasterSecret)
->addExtension(new SignatureAlgorithms(
  SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
  SignatureAlgorithm::RSA_PKCS1_SHA256,
  SignatureAlgorithm::RSA_PSS_PSS_SHA256
))
->addExtension(new SupportedGroups(
  SupportedGroup::SECP256R1
))
;

$context->addHandshake($client_hello);

socket_write($socket, Record::handshake(Version::TLS_12, $client_hello));

foreach(Record::parse(socket_read($socket, 8192), $context) as $record){
  if($record->getType() === RecordType::HANDSHAKE){
    $payload = $record->getPayload();

    if($payload instanceof ServerHello) $server_hello = $payload;

    $context->addHandshake($payload);
  }
}

if(!isset($server_hello)){
  die("ServerHello not received from server. Terminating connection.\n");
}

$cipher_suite = $server_hello->getCipherSuite();
$client_key_exchange = new ClientKeyExchange($context);
$cipher = null;

$client_key_exchange->setPSKIdentity($psk_identity);

$context->addHandshake($client_key_exchange);

// Additional handling for RSA key exchange if needed
if(str_contains($cipher_suite->name, 'RSA')){
  /** @var Certificate */
  $certificate = $context->getHandshake(HandshakeType::CERTIFICATE);  
  $premaster_secret = openssl_random_pseudo_bytes(48);
  
  openssl_public_encrypt($premaster_secret, $encrypted_data, $certificate->getCertificate(0));

  $client_key_exchange->setParam(new RSAParam($encrypted_data));
}

socket_write(
  $socket, 
  Record::handshake(Version::TLS_12, $client_key_exchange).
  Record::changeCipherSpec(Version::TLS_12)
);

$client_random = $client_hello->getRandom();
$server_random = $server_hello->getRandom();

if($client_hello->hasExtension(ExtensionType::EXTENDED_MASTER_SECRET)){
  $master_secret = Crypto::PRF(
    $cipher_suite,
    $premaster_secret,
    'extended master secret',
    $context->getHandshakeHash(),
    48
  );
}
else{
  $master_secret = Crypto::PRF(
    $cipher_suite,
    $premaster_secret,
    'master secret',
    "$client_random$server_random",
    48
  );
}

$key_block = Crypto::PRF(
  $cipher_suite, 
  $master_secret, 
  'key expansion',
  "$server_random$client_hello",
  128
);

if($cipher_suite->isAEAD()){
  $cipher = new AEADCipher('client', $cipher_suite, $key_block);
}
else{
  $cipher = new BlockCipher('client', $cipher_suite, $key_block);
}

$verify_data = Crypto::PRF(
  $cipher_suite,
  $master_secret,
  'client finished',
  $context->getHandshakeHash(),
  12
);

$iv = openssl_random_pseudo_bytes(16);

$finished = new Finished($context);
$finished->setVerifyData($verify_data);

if($client_hello->hasExtension(ExtensionType::ENCRYPT_THEN_MAC)){
  $plaintext = Crypto::pad((string) $finished, 16);

  $ciphertext = openssl_encrypt(
    $plaintext,
    'AES-128-CBC',
    $cipher->getWriteKey(),
    OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
    $iv
  );

  $mac = Crypto::HMACRecord(
    $cipher_suite, 
    0, 
    $cipher->getMacKey(), 
    Record::handshake(Version::TLS_12, $iv.$ciphertext)
  );

  $ciphertext .= $mac;
}
else{
  $mac = Crypto::HMACRecord(
    $cipher_suite, 
    0, 
    $cipher->getMacKey(), 
    Record::handshake(Version::TLS_12, $finished)
  );
  
  $plaintext = $finished . $mac;
  $plaintext = Crypto::pad($plaintext, 16);
  
  $ciphertext = openssl_encrypt(
    $plaintext,
    'AES-128-CBC',
    $cipher->getWriteKey(),
    OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
    $iv
  );
}

socket_write($socket, Record::handshake($version, $iv.$ciphertext));
