<?php
namespace TLS\Enums;

use Deprecated;
use Exception;

enum SupportedGroup : int{
  case SECT163K1 = 1;
  case SECT163R1 = 2;
  case SECT163R2 = 3;
  case SECT193R1 = 4;
  case SECT193R2 = 5;
  case SECT233K1 = 6;
  case SECT233R1 = 7;
  case SECT239K1 = 8;
  case SECT283K1 = 9;
  case SECT283R1 = 10;
  case SECT409K1 = 11;
  case SECT409R1 = 12;
  case SECT571K1 = 13;
  case SECT571R1 = 14;
  case SECP160K1 = 15;
  case SECP160R1 = 16;
  case SECP160R2 = 17;
  case SECP192K1 = 18;
  case SECP192R1 = 19;
  case SECP224K1 = 20;
  case SECP224R1 = 21;
  case SECP256K1 = 22;
  case SECP256R1 = 23;
  case SECP384R1 = 24;
  case SECP521R1 = 25;
  case BRAINPOOLP256R1 = 26;
  case BRAINPOOLP384R1 = 27;
  case BRAINPOOLP512R1 = 28;
  case X25519 = 29;
  case X448 = 30;
  case BRAINPOOLP256R1TLS13 = 31;
  case BRAINPOOLP384R1TLS13 = 32;
  case BRAINPOOLP512R1TLS13 = 33;
  case GC256A = 34;
  case GC256B = 35;
  case GC256C = 36;
  case GC256D = 37;
  case GC512A = 38;
  case GC512B = 39;
  case GC512C = 40;
  case CURVESM2 = 41;
  case FFDHE2048 = 256;
  case FFDHE3072 = 257;
  case FFDHE4096 = 258;
  case FFDHE6144 = 259;
  case FFDHE8192 = 260;
  case MLKEM512 = 512;
  case MLKEM768 = 513;
  case MLKEM1024 = 514;
  case SECP256R1MLKEM768 = 4587;
  case X25519MLKEM768 = 4588;
  case SECP384R1MLKEM1024 = 4589;
  case CURVESM2MLKEM768 = 4590;
  case X25519KYBER768DRAFT00 = 25497;
  case SECP256R1KYBER768DRAFT00 = 25498;
  case ARBITRARY_EXPLICIT_PRIME_CURVES = 65281;
  case ARBITRARY_EXPLICIT_CHAR2_CURVES = 65282;

  /**
   * List of unsupported curves for the TLS library 
   */
  private static function isUnsupported(self $group): bool{
    return in_array($group, [
      self::ARBITRARY_EXPLICIT_CHAR2_CURVES,
      self::ARBITRARY_EXPLICIT_PRIME_CURVES,
      self::BRAINPOOLP256R1,
      self::BRAINPOOLP384R1,
      self::BRAINPOOLP512R1,
      self::BRAINPOOLP256R1TLS13,
      self::BRAINPOOLP384R1TLS13,
      self::BRAINPOOLP512R1TLS13,
      self::CURVESM2,
      self::CURVESM2MLKEM768,
      self::FFDHE2048,
      self::FFDHE3072,
      self::FFDHE4096,
      self::FFDHE6144,
      self::FFDHE8192,
      self::GC256A,
      self::GC256B,
      self::GC256C,
      self::GC256D,
      self::GC512A,
      self::GC512B,
      self::GC512C,
      self::MLKEM512,
      self::MLKEM768,
      self::MLKEM1024,
      self::SECP256R1KYBER768DRAFT00,
      self::SECP256R1MLKEM768,
      self::SECP384R1MLKEM1024,
      self::X25519,
      self::X25519KYBER768DRAFT00,
      self::X25519MLKEM768,
      self::X448
    ], true);
  } 

  public function getOpenSSLName(): string{
    if(self::isUnsupported($this)){
      throw new Exception("Unsupported curve: " . $this->name);
    }

    if($this->value === SupportedGroup::SECP256R1->value){
      return 'prime256v1';
    }

    return $this->name;
  }

  public static function getOID(self $group): array{
    if(self::isUnsupported($group)){
      throw new Exception("Unsupported curve: " . $group->name);
    }

    return match($group){
      self::SECT163K1 => [1, 3, 132, 0, 1],
      self::SECT163R1 => [1, 3, 132, 0, 2],
      self::SECT163R2 => [1, 3, 132, 0, 15],
      self::SECT193R1 => [1, 3, 132, 0, 24],
      self::SECT193R2 => [1, 3, 132, 0, 25],
      self::SECT233K1 => [1, 3, 132, 0, 26],
      self::SECT233R1 => [1, 3, 132, 0, 27],
      self::SECT239K1 => [1, 3, 132, 0, 3],
      self::SECT283K1 => [1, 3, 132, 0, 16],
      self::SECT283R1 => [1, 3, 132, 0, 17],
      self::SECT409K1 => [1, 3, 132, 0, 36],
      self::SECT409R1 => [1, 3, 132, 0, 37],
      self::SECT571K1 => [1, 3, 132, 0, 38],
      self::SECT571R1 => [1, 3, 132, 0, 39],
      self::SECP160R1 => [1, 3, 132, 0, 8],
      self::SECP160K1 => [1, 3, 132, 0, 9],
      self::SECP160R2 => [1, 3, 132, 0, 30],
      self::SECP192K1 => [1, 3, 132, 0, 31],
      self::SECP192R1 => [1, 2, 840, 10045, 3, 1, 1],
      self::SECP224K1 => [1, 3, 132, 0, 32],
      self::SECP224R1 => [1, 3, 132, 0, 33],
      self::SECP256K1 => [1, 3, 132, 0, 10],
      self::SECP256R1 => [1, 2, 840, 10045, 3, 1, 7],
      self::SECP384R1 => [1, 3, 132, 0, 34],
      self::SECP521R1 => [1, 3, 132, 0, 35]
    };
  }
}