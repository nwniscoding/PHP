<?php
namespace nwniscoding\TLS;

use InvalidArgumentException;
use nwniscoding\TLS\Enums\ExtensionType;
use function strlen;
use function array_key_exists;

final class KeySchedule{
  public const string TLS_12_MASTER_SECRET_LABEL = "master secret";

  public const string TLS_12_EXTENDED_MASTER_SECRET_LABEL = "extended master secret";

  public const string TLS_12_KEY_EXPANSION_LABEL = "key expansion";

  public const string TLS_12_CLIENT_FINISHED_LABEL = "client finished";

  public const string TLS_12_SERVER_FINISHED_LABEL = "server finished";

  public static function prf(string $secret, string $label, string $seed, int $length, string $hash = 'SHA256') : string{
    $result = '';
    $a = "{$label}{$seed}";
    
    while(strlen($result) < $length){
      $a = hash_hmac($hash, $a, $secret, true);
      $result .= hash_hmac($hash, "{$a}{$label}{$seed}", $secret, true);
    }
    
    return substr($result, 0, $length);
  }

  public static function deriveMasterSecret(string $sharedSecret, HandshakeContext $context) : string{
    $clientHello = $context->getClientHello();
    $serverHello = $context->getServerHello();

    if($clientHello === null || $serverHello === null){
      throw new InvalidArgumentException("ClientHello and ServerHello must be set in the handshake context to derive the master secret");
    }

    $extendedMasterSecret = array_key_exists(ExtensionType::EXTENDED_MASTER_SECRET->value, $clientHello->extensions);
    $info = $context->getCipherInfo();

    if($extendedMasterSecret){
      $label = self::TLS_12_EXTENDED_MASTER_SECRET_LABEL;
      $data = $context->getHandshakeHash();
    }
    else{
      $label = self::TLS_12_MASTER_SECRET_LABEL;
      $data = "{$clientHello->random}{$serverHello->random}";
    }

    return self::prf($sharedSecret, $label, $data, 48, $info->mac);
  }

  public static function deriveKeyBlock(string $masterSecret, HandshakeContext $context) : string{
    $clientHello = $context->getClientHello();
    $serverHello = $context->getServerHello();
    $info = $context->getCipherInfo();

    if($clientHello === null || $serverHello === null){
      throw new InvalidArgumentException("ClientHello and ServerHello must be set in the handshake context to derive the key block");
    }

    return self::prf(
      $masterSecret, 
      self::TLS_12_KEY_EXPANSION_LABEL, 
      "{$serverHello->random}{$clientHello->random}", 
      2 * ($info->getKeySize() + $info->getMacSize() + $info->getIVSize()),
      $info->mac
    );
  }

  public static function verifyFinished(string $masterSecret, string $label, HandshakeContext $context) : string{
    return self::prf($masterSecret, $label, $context->getHandshakeHash(), 12, $context->getCipherInfo()->mac);
  }
}