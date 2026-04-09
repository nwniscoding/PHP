<?php
namespace nwniscoding\TLS\Enums;

use Exception;
use OpenSSLAsymmetricKey;
use nwniscoding\ASN1\ASN1Factory;

/**
 * Enumeration of TLS Supported Groups (Elliptic Curves and Finite Field Groups) as per IANA registry.
 */
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
   * Get OID of the curve.
   * @throws Exception if OID is not defined for the curve.
   * @return int[] Array of integers representing the OID.
   */
  public function getOID(): array{
    return match($this){
      self::X25519 => [1, 3, 101, 110],
      self::X448 => [1, 3, 101, 111],
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
      self::SECP160K1 => [1, 3, 132, 0, 9],
      self::SECP160R1 => [1, 3, 132, 0, 8],
      self::SECP160R2 => [1, 3, 132, 0, 30],
      self::SECP192K1 => [1, 3, 132, 0, 31],
      self::SECP192R1 => [1, 2, 840, 10045, 3, 1, 1],
      self::SECP224K1 => [1, 3, 132, 0, 32],
      self::SECP224R1 => [1, 3, 132, 0, 33],
      self::SECP256K1 => [1, 3, 132, 0, 10],
      self::SECP256R1 => [1, 2, 840, 10045, 3, 1, 7],
      self::SECP384R1 => [1, 3, 132, 0, 34],
      self::SECP521R1 => [1, 3, 132, 0, 35],
      self::BRAINPOOLP256R1, self::BRAINPOOLP256R1TLS13 => [1, 3, 36, 3, 3, 2, 8, 1, 1, 7],
      self::BRAINPOOLP384R1, self::BRAINPOOLP384R1TLS13 => [1, 3, 36, 3, 3, 2, 8, 1, 1, 11],
      self::BRAINPOOLP512R1, self::BRAINPOOLP512R1TLS13 => [1, 3, 36, 3, 3, 2, 8, 1, 1, 13],
      default => throw new Exception("OID not defined for this curve")
    };
  }

  /**
   * Get the standard name of the curve as recognized by OpenSSL. 
   * @throws Exception if name is not defined for the curve.
   * @return string Name of the curve.
   */
  public function getName(): string{
    return match($this){
      self::SECT163K1 => "sect163k1",
      self::SECT163R1 => "sect163r1",
      self::SECT163R2 => "sect163r2",
      self::SECT193R1 => "sect193r1",
      self::SECT193R2 => "sect193r2",
      self::SECT233K1 => "sect233k1",
      self::SECT233R1 => "sect233r1",
      self::SECT239K1 => "sect239k1",
      self::SECT283K1 => "sect283k1",
      self::SECT283R1 => "sect283r1",
      self::SECT409K1 => "sect409k1",
      self::SECT409R1 => "sect409r1",
      self::SECT571K1 => "sect571k1",
      self::SECT571R1 => "sect571r1",
      self::SECP160K1 => "secp160k1",
      self::SECP160R1 => "secp160r1",
      self::SECP160R2 => "secp160r2",
      self::SECP192K1 => "secp192k1",
      self::SECP192R1 => "secp192r1",
      self::SECP224K1 => "secp224k1",
      self::SECP224R1 => "secp224r1",
      self::SECP256K1 => "secp256k1",
      self::SECP256R1 => "prime256v1",
      self::SECP384R1 => "secp384r1",
      self::SECP521R1 => "secp521r1",
      self::BRAINPOOLP256R1, self::BRAINPOOLP256R1TLS13 => "brainpoolP256r1",
      self::BRAINPOOLP384R1, self::BRAINPOOLP384R1TLS13 => "brainpoolP384r1",
      self::BRAINPOOLP512R1, self::BRAINPOOLP512R1TLS13 => "brainpoolP512r1",
      default => throw new Exception("Name not defined for this curve")
    };
  }

  /**
   * Create a new private key for this curve using OpenSSL. If the curve is not supported by OpenSSL, this method will throw an exception.
   * @throws Exception if the curve is not supported for key generation.
   * @return OpenSSLAsymmetricKey The generated private key as an OpenSSLAsymmetricKey object.
   */
  public function createPrivateKey() : OpenSSLAsymmetricKey{
    $options = match($this){
      self::X25519 => [
        'private_key_type' => OPENSSL_KEYTYPE_X25519
      ],
      self::X448 => [
        'private_key_type' => OPENSSL_KEYTYPE_X448
      ],
      default => [
        'private_key_type' => OPENSSL_KEYTYPE_EC,
        'curve_name' => $this->getName()
      ]
    };

    return openssl_pkey_new($options);
  }

  /**
   * Wrap a public key in PEM format
   * @param string $data Raw public key data
   * @return string ASN.1 encoded public key
   */
  public function wrapPublicKey(string $data) : string{
    $asn = match($this){
      self::X25519, self::X448 => ASN1Factory::sequence(
        ASN1Factory::sequence(
          ASN1Factory::objectIdentifier($this->getOID())
        ),
        ASN1Factory::bitString($data)
      ),
      default => ASN1Factory::sequence(
        ASN1Factory::sequence(
          ASN1Factory::objectIdentifier([1, 2, 840, 10045, 2, 1]),
          ASN1Factory::objectIdentifier($this->getOID())
        ),
        ASN1Factory::bitString($data)
      )
    };

    $asn = base64_encode($asn);

    return <<<PEM
    -----BEGIN PUBLIC KEY-----
    $asn
    -----END PUBLIC KEY-----
    PEM;
  }

  /**
   * Export the public key from the given OpenSSLAsymmetricKey object in the format expected for TLS key exchange messages. The exact format depends on the curve type. For X25519 and X448, it will be the raw public key bytes. For other curves, it will be the uncompressed point format (0x04 || X || Y).
   * @throws Exception if the curve is not supported for public key export or if the key is not compatible with the curve.
   * @param OpenSSLAsymmetricKey $key The OpenSSLAsymmetricKey object containing the public key to export.
   * @return string The exported public key data in the format expected for TLS key exchange messages.
   */
  public function exportPublicKey(OpenSSLAsymmetricKey $key) : string{
    $details = openssl_pkey_get_details($key);
    $bits = $details['bits'] >> 3;

    if($bits % 2 !== 0){
      $bits += 1;
    }

    return match($this){
      self::X25519 => $details['x25519']['pub_key'],
      self::X448 => $details['x448']['pub_key'],
      default => "\x4" . 
      self::padString($details['ec']['x'], $bits) . 
      self::padString($details['ec']['y'], $bits)
    };
  }

  /**
   * Pad a binary string with leading zeros to the specified length. 
   * @param string $data The binary string to pad.
   * @param int $length The desired length of the output string after padding. If the input string is already equal to or longer than this length, it will be returned unchanged.
   * @return string The padded binary string, with leading zeros added if necessary to reach the specified length.
   */
  private static function padString(string $data, int $length) : string{
    return str_pad($data, $length, "\x00", STR_PAD_LEFT);
  }
}