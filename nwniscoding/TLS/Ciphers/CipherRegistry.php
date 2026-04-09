<?php
namespace nwniscoding\TLS\Ciphers;

use InvalidArgumentException;
use nwniscoding\TLS\Enums\CipherSuite;

final class CipherRegistry{
  private static array $registry = [];

  public static function registerCipher(CipherSuite $cipherSuite, CipherInfo $info) : void{
    self::$registry[$cipherSuite->value] = $info;
  }

  public static function getCipher(CipherSuite $cipherSuite) : CipherInfo{
    if(!isset(self::$registry[$cipherSuite->value])){
      throw new InvalidArgumentException("Cipher suite {$cipherSuite->name} is not registered");
    }
    
    return self::$registry[$cipherSuite->value];
  }
}