<?php
use TLS\Enums\CipherSuite;
use TLS\Enums\ExtensionType;
use TLS\Enums\HandshakeType;
use TLS\Enums\RecordType;
use TLS\Enums\Version;
use TLS\Extensions\EncryptThenMAC;
use TLS\Handshakes\ClientHello;
use TLS\Handshakes\ClientKeyExchange;
use TLS\Handshakes\Finished;
use TLS\Handshakes\Handshake;
use TLS\Record;
use TLS\Utils\Crypto;

/**
 * This is a simple TLS client that only supports PSK cipher suites.
 * It uses Encrypt-then-MAC and MAC-then-encrypt based on the server's support.
 */
spl_autoload_register('spl_autoload');

$handshakes = [];
$cipher = CipherSuite::TLS_PSK_WITH_AES_128_CBC_SHA256;
$psk = hex2bin('1a2b3c4d5e6f7081');
$psk_identity = 'myidentity';
$psk_len = strlen($psk);
$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);

$premaster_secret = pack(
  'na*na*',
  $psk_len,
  str_repeat("\0", $psk_len),
  $psk_len,
  $psk
);

socket_connect($socket, 'localhost', 9000);

$client_hello = new ClientHello();
$client_hello
->setVersion(Version::TLS_12)
->addCipherSuite($cipher)
->addExtension(new EncryptThenMAC())
; // Disable this line to test without ETM

$handshakes[] = $client_hello;

socket_write(
  $socket, 
  Record::handshake(Version::TLS_12, $client_hello)
);

foreach(Record::parse(socket_read($socket, 8192)) as $record){
  if($record->getType() === RecordType::HANDSHAKE){
    $handshakes[] = $handshake = $record->getPayload();

    if($handshake->getType() === HandshakeType::SERVER_HELLO) $server_hello = $handshake;
  }
}

$client_key_exchange = new ClientKeyExchange();
$client_key_exchange
->setPSKIdentity($psk_identity);

$server_hello = $handshakes[1]; 
$handshakes[] = $client_key_exchange;

$client_random = $client_hello->getRandom();
$server_random = substr($server_hello, 6, 32);

socket_write(
  $socket, 
  Record::handshake(Version::TLS_12, $client_key_exchange).
  Record::changeCipherSpec(Version::TLS_12)
);

$master_secret = Crypto::PRF(
  $cipher,
  $premaster_secret,
  'master secret',
  "$client_random$server_random",
  48
);

$client = Crypto::generateKey(
  $cipher,
  $master_secret,
  $client_random,
  $server_random
)['client'];

$iv = openssl_random_pseudo_bytes(16);
$verify_data = Crypto::PRF(
  $cipher,
  $master_secret,
  'client finished',
  hash('sha256', join('', $handshakes), true),
  12
);

$finished = new Finished();
$finished->createMAC($cipher, $master_secret, 'client', $handshakes);

if($client_hello->hasExtension(ExtensionType::ENCRYPT_THEN_MAC)){
  $plaintext = Crypto::pad($finished, 16);

  $ciphertext = openssl_encrypt(
    $plaintext,
    'AES-128-CBC',
    $client['key'],
    OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
    $iv
  );

  $mac = Crypto::HMACRecord(
    $cipher, 
    0, 
    $client['mac'], 
    Record::handshake(Version::TLS_12, $iv.$ciphertext)
  );

  $ciphertext .= $mac;
}
else{
  $mac = Crypto::HMACRecord(
    $cipher, 
    0, 
    $client['mac'], 
    Record::handshake(Version::TLS_12, $finished)
  );
  
  $plaintext = $finished . $mac;
  $plaintext = Crypto::pad($plaintext, 16);
  
  $ciphertext = openssl_encrypt(
    $plaintext,
    'AES-128-CBC',
    $client['key'],
    OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
    $iv
  );
}

socket_write(
  $socket,
  Record::handshake(Version::TLS_12, $iv.$ciphertext)
);

sleep(5);

socket_write($socket, 'test');