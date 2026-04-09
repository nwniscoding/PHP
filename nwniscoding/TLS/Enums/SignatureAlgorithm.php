<?php
namespace nwniscoding\TLS\Enums;

/**
 * Enumeration of TLS Signature Algorithms as per IANA registry.
 */
enum SignatureAlgorithm : int{
  case RSA_PKCS1_SHA1 = 0x0201;
  
  case ECDSA_SHA1 = 0x0203;
  
  case RSA_PKCS1_SHA256 = 0x0401;
  
  case ECDSA_SECP256R1_SHA256 = 0x0403;
  
  case ECDSA_SECP384R1_SHA384 = 0x0503;
  
  case ECDSA_SECP521R1_SHA512 = 0x0603;
  
  case ED25519 = 0x0807;
  
  case ED448 = 0x0808;
  
  case ECDSA_BRAINPOOLP256R1TLS13_SHA256 = 0x081A;
  
  case ECDSA_BRAINPOOLP384R1TLS13_SHA384 = 0x081B;
  
  case ECDSA_BRAINPOOLP512R1TLS13_SHA512 = 0x081C;
  
  case RSA_PSS_PSS_SHA256 = 0x0809;
  
  case RSA_PSS_PSS_SHA384 = 0x080A;
  
  case RSA_PSS_PSS_SHA512 = 0x080B;
  
  case RSA_PSS_RSAE_SHA256 = 0x0804;
  
  case RSA_PSS_RSAE_SHA384 = 0x0805;
  
  case RSA_PSS_RSAE_SHA512 = 0x0806;
  
  case RSA_PKCS1_SHA384 = 0x0501;
  
  case RSA_PKCS1_SHA512 = 0x0601;
  
  case SHA224_ECDSA = 0x0303;
  
  case SHA224_RSA = 0x0301;
  
  case SHA224_DSA = 0x0302;
  
  case SHA256_DSA = 0x0402;
  
  case SHA384_DSA = 0x0502;
  
  case SHA512_DSA = 0x0602;
  
  case ECCSI_SHA256 = 0x0704;
  
  case ISO_IBS1 = 0x0705;
  
  case ISO_IBS2 = 0x0706;
  
  case ISO_CHINESE_IBS = 0x0707;
	
  case SM2SIG_SM3 = 0x0708;	
	
  case GOSTR34102012_256A = 0x0709;	
	
  case GOSTR34102012_256B = 0x070A;	
	
  case GOSTR34102012_256C = 0x070B;	
	
  case GOSTR34102012_256D = 0x070C;	
	
  case GOSTR34102012_512A = 0x070D;	
	
  case GOSTR34102012_512B = 0x070E;	
	
  case GOSTR34102012_512C = 0x070F;
	
  case MLDSA44 = 0x0904;	
	
  case MLDSA65 = 0x0905;	
	
  case MLDSA87 = 0x0906;	
	
  case SLHDSA_SHA2_128S = 0x0911;	
	
  case SLHDSA_SHA2_128F = 0x0912;	
	
  case SLHDSA_SHA2_192S = 0x0913;	
	
  case SLHDSA_SHA2_192F = 0x0914;	
	
  case SLHDSA_SHA2_256S = 0x0915;	
	
  case SLHDSA_SHA2_256F = 0x0916;	
	
  case SLHDSA_SHAKE_128S = 0x0917;	
	
  case SLHDSA_SHAKE_128F = 0x0918;	
	
  case SLHDSA_SHAKE_192S = 0x0919;	
	
  case SLHDSA_SHAKE_192F = 0x091A;	
	
  case SLHDSA_SHAKE_256S = 0x091B;	
  
	case SLHDSA_SHAKE_256F = 0x091C;

  /**
   * Get the corresponding hash for the signature algorithm, if it is supported by OpenSSL. If the algorithm does not have a specific hash function associated with it or is not supported by OpenSSL, this method returns null.
   * @return ?int
   */
  public function getHash() : ?int{
    return match($this){
      // SHA-1 is considered weak and should not be used.
      self::RSA_PKCS1_SHA1,
      self::ECDSA_SHA1 => OPENSSL_ALGO_SHA1,
      // SHA-256 is widely used and considered secure for most applications.
      self::RSA_PKCS1_SHA256,
      self::ECDSA_SECP256R1_SHA256,
      self::ECDSA_BRAINPOOLP256R1TLS13_SHA256,
      self::RSA_PSS_PSS_SHA256,
      self::RSA_PSS_RSAE_SHA256,
      self::ECCSI_SHA256,
      self::SHA256_DSA => OPENSSL_ALGO_SHA256,
      // SHA-384 is also considered secure and is often used in high-security applications.
      self::ECDSA_BRAINPOOLP384R1TLS13_SHA384,
      self::ECDSA_SECP384R1_SHA384,
      self::RSA_PSS_PSS_SHA384,
      self::RSA_PSS_RSAE_SHA384,
      self::RSA_PKCS1_SHA384,
      self::SHA384_DSA => OPENSSL_ALGO_SHA384,
      // SHA-512 is considered very secure and is used in applications that require a high level of security, but it is also slower than SHA-256 and SHA-384.
      self::ECDSA_SECP521R1_SHA512,
      self::ECDSA_BRAINPOOLP512R1TLS13_SHA512,
      self::RSA_PSS_PSS_SHA512,
      self::RSA_PSS_RSAE_SHA512,
      self::SHA512_DSA,
      self::RSA_PKCS1_SHA512 => OPENSSL_ALGO_SHA512,
      // SHA-224 is less commonly used and is considered less secure than SHA-256, but it may still be used in some legacy applications.
      self::SHA224_ECDSA,
      self::SHA224_RSA,
      self::SHA224_DSA => OPENSSL_ALGO_SHA224,
      // The following algorithms do not have a specific hash function associated with them or are not supported by OpenSSL, so we return null.
      self::ED25519,
      self::ED448,
      self::ISO_IBS1,
      self::ISO_IBS2,
      self::ISO_CHINESE_IBS,
      self::SM2SIG_SM3,	
      self::GOSTR34102012_256A,	
      self::GOSTR34102012_256B,	
      self::GOSTR34102012_256C,	
      self::GOSTR34102012_256D,	
      self::GOSTR34102012_512A,	
      self::GOSTR34102012_512B,	
      self::GOSTR34102012_512C,
      self::MLDSA44,	
      self::MLDSA65,	
      self::MLDSA87,	
      self::SLHDSA_SHA2_128S,	
      self::SLHDSA_SHA2_128F,	
      self::SLHDSA_SHA2_192S,	
      self::SLHDSA_SHA2_192F,	
      self::SLHDSA_SHA2_256S,	
      self::SLHDSA_SHA2_256F,	
      self::SLHDSA_SHAKE_128S,	
      self::SLHDSA_SHAKE_128F,	
      self::SLHDSA_SHAKE_192S,	
      self::SLHDSA_SHAKE_192F,	
      self::SLHDSA_SHAKE_256S,	
      self::SLHDSA_SHAKE_256F => null
    };
  }
}