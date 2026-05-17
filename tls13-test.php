<?php

use nwniscoding\IO\BufferReader;
use nwniscoding\TLS\Enums\CipherSuite;
use nwniscoding\TLS\Enums\ExtensionType;
use nwniscoding\TLS\Enums\RecordType;
use nwniscoding\TLS\Enums\SignatureAlgorithm;
use nwniscoding\TLS\Enums\SupportedGroup;
use nwniscoding\TLS\Enums\Version;
use nwniscoding\TLS\Extensions\KeyShare;
use nwniscoding\TLS\Extensions\SignatureAlgorithms;
use nwniscoding\TLS\Extensions\SupportedGroups;
use nwniscoding\TLS\Extensions\SupportedVersion;
use nwniscoding\TLS\Handshakes\ClientHello;
use nwniscoding\TLS\Handshakes\ServerHello;
use nwniscoding\TLS\Keyschedules\TLS13KeySchedule;
use nwniscoding\TLS\KeyShareEntry;
use nwniscoding\TLS\Record;
use nwniscoding\TLS\RecordParser;
use nwniscoding\TLS\Sessions\ClientSession;
use nwniscoding\TLS\TLSContext;
spl_autoload_register();

function socket_read_all($socket){
  $data = '';

  $data = socket_read($socket, 4096);
  // while(true){
  //   $chunk = socket_read($socket, 4096);

  //   if($chunk === false || $chunk === ''){
  //     break;
  //   }

  //   $data .= $chunk;
  // }

  return $data;
}

function TLS13extract(string $inputKeyMaterial, string $salt, string $hash, int $hashLength) : string{
    if($salt === ''){
      $salt = str_repeat("\0", $hashLength);
    }

    return hash_hmac($hash, $inputKeyMaterial, $salt, true);
  }

  function TLS13expand(string $secret, string $label, string $context, int $length, string $hash, int $hashLength) : string{
    $ctx = pack('nCa*Ca*', $length, strlen($label), $label, strlen($context), $context);

    $n = ceil($length / $hashLength);
    $outputKeyMaterial = '';
    $t = '';

    for($i = 1; $i <= $n; $i++){
      $c = chr($i);
      $t = hash_hmac($hash, "{$t}{$ctx}{$c}", $secret, true);
      $outputKeyMaterial .= $t;
    }

    return substr($outputKeyMaterial, 0, $length);
  }

$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_connect($socket, 'localhost', 9000);

$session = new ClientSession($socket, new TLSContext(Version::TLS_13));
$clientHello = new ClientHello(
  Version::TLS_12, 
  null, 
  '', 
  [ CipherSuite::TLS_AES_128_GCM_SHA256 ], 
  [
    new SupportedGroups([ SupportedGroup::X25519 ]),
    new SignatureAlgorithms(SignatureAlgorithm::cases()),
    new SupportedVersion([ Version::TLS_12, Version::TLS_13 ]),
    new KeyShare([
      new KeyShareEntry(SupportedGroup::X25519)
    ])
  ]
);

socket_write($socket, Record::handshake(Version::TLS_12, $clientHello)->toBinary());

$data = new BufferReader(socket_read_all($socket));
$serverHello = null;
$keys = [];
$seq = 0;

$encryptedData = [];
foreach(RecordParser::parse($data, $session) as $record){
  if($record->type === RecordType::HANDSHAKE && $record->content instanceof ServerHello){
    $serverHello = $record->content;
    $clientKeyShare = $clientHello->extensions[ExtensionType::KEY_SHARE->value] ?? null;
    $serverKeyShare = $serverHello->extensions[ExtensionType::KEY_SHARE->value] ?? null;

    $serverKeyEntry = $serverKeyShare->getCurrentKeyShare();
    $clientKeyEntry = $clientKeyShare->getKeyShareByGroup($serverKeyEntry->group);
    $sharedSecret = openssl_pkey_derive($serverKeyEntry->group->wrapPublicKey($serverKeyEntry->publicKey), $clientKeyEntry->privateKey);

    $helloHash = hash('sha256', "{$clientHello->toBinary()}{$serverHello->toBinary()}", true);
    $zeroKey = str_repeat("\0", 32);
    $earlySecret = TLS13extract($zeroKey, $zeroKey, 'sha256', 32);
    $emptyHash = hash('sha256', '', true);
    $derivedSecret = TLS13expand($earlySecret, "tls13 derived", $emptyHash, 32, 'sha256', 32);
    $handshakeSecret = TLS13extract($sharedSecret, $derivedSecret, 'sha256', 32);
    $serverHandshakeTrafficSecret = TLS13expand($handshakeSecret, "tls13 s hs traffic", $helloHash, 32, 'sha256', 32);
    $clientHandshakeTrafficSecret = TLS13expand($handshakeSecret, "tls13 c hs traffic", $helloHash, 32, 'sha256', 32);
    $serverKey = TLS13expand($serverHandshakeTrafficSecret, "tls13 key", '', 16, 'sha256', 32); // AES-128 key is 16 bytes
    $serverIV = TLS13expand($serverHandshakeTrafficSecret, "tls13 iv", '', 12, 'sha256', 32);
    $clientKey = TLS13expand($clientHandshakeTrafficSecret, "tls13 key", '', 16, 'sha256', 32);
    $clientIV = TLS13expand($clientHandshakeTrafficSecret, "tls13 iv", '', 12, 'sha256', 32);

    $keys = [
      'clientKey' => $clientKey,
      'clientIV' => $clientIV,
      'serverKey' => $serverKey,
      'serverIV' => $serverIV
    ];
  }
  else if($record->type === RecordType::APPLICATION_DATA){
    $content = $record->content;
    $data = substr($content, 0, -16);
    $authTag = substr($content, -16);
    $decrypted = openssl_decrypt(
      $data, 
      'aes-128-gcm', 
      $keys['serverKey'], 
      OPENSSL_RAW_DATA, 
      $keys['serverIV'] ^ str_pad(chr($seq++), 12, "\0", STR_PAD_LEFT), 
      $authTag,
      pack('Cn2', RecordType::APPLICATION_DATA->value, 0x0303, strlen($content))
    );

    $encryptedData[] = $decrypted;
  }
}

var_dump(join('', array_map('bin2hex', $encryptedData)));