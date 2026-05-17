<?php
namespace nwniscoding\TLS\KeySchedules;

use nwniscoding\TLS\Ciphers\Cipher;
use nwniscoding\TLS\Ciphers\TLS12AEADCipher;
use nwniscoding\TLS\Ciphers\TLS12BlockCipher;
use nwniscoding\TLS\Exceptions\TLSException;
use function strlen;
use function array_key_exists;

use nwniscoding\TLS\Enums\ExtensionType;
use nwniscoding\TLS\Exceptions\HandshakeException;
use nwniscoding\TLS\Ciphers\CipherInfo;
use nwniscoding\TLS\HandshakeContext;

final class TLS12KeySchedule implements KeySchedule{
  public const string TLS_12_MASTER_SECRET_LABEL = "master secret";

  public const string TLS_12_EXTENDED_MASTER_SECRET_LABEL = "extended master secret";

  public const string TLS_12_KEY_EXPANSION_LABEL = "key expansion";

  public const string TLS_12_CLIENT_FINISHED_LABEL = "client finished";

  public const string TLS_12_SERVER_FINISHED_LABEL = "server finished";

  private ?string $masterSecret = null;

  private ?string $keyExpansion = null;

  private HandshakeContext $context;

  public function __construct(HandshakeContext $context){
    $this->context = $context;
  }

  public function deriveKey(string $sharedSecret) : void{
    $context = $this->context;
    $clientHello = $context->getClientHello();
    $serverHello = $context->getServerHello();
    $info = $context->getCipherInfo();

    if($clientHello === null || $serverHello === null){
      throw new HandshakeException("ClientHello and ServerHello must be set in the handshake context to derive the master secret");
    }

    if(array_key_exists(ExtensionType::EXTENDED_MASTER_SECRET->value, $clientHello->extensions)){
      $label = self::TLS_12_EXTENDED_MASTER_SECRET_LABEL;
      $seed = $context->getHandshakeHash();
    }
    else{
      $label = self::TLS_12_MASTER_SECRET_LABEL;
      $seed = "{$clientHello->random}{$serverHello->random}";
    }

    $keyExpansionSeed = "{$serverHello->random}{$clientHello->random}";

    $this->masterSecret = self::PRF($sharedSecret, $label, $seed, 48, $info);
    $this->keyExpansion = self::PRF($this->masterSecret, self::TLS_12_KEY_EXPANSION_LABEL, $keyExpansionSeed, 256, $info);
  }

  public function verifyData(string $finishedLabel) : string{
    $context = $this->context;
    
    if($this->masterSecret === null){
      throw new TLSException("Master secret must be derived before verifying finished message");
    }

    return self::PRF($this->masterSecret, $finishedLabel, $context->getHandshakeHash(), 12, $context->getCipherInfo());
  }

  public function getClientKey() : Cipher{
    $info = $this->context->getCipherInfo();
    $ivSize = $info->encryption === 'chacha20-poly1305' ? $info->getIVSize() : 4;
    $keySize = $info->getKeySize();
    $macSize = $info->getMacSize();
    $keyblock = $this->keyExpansion;
    $encryptThenMAC = array_key_exists(ExtensionType::ENCRYPT_THEN_MAC->value, $this->context->getClientHello()->extensions);
    
    if($this->keyExpansion === null){
      throw new TLSException("Key expansion must be derived before getting client key");
    }

    return $info->isAEAD() ? 
      new TLS12AEADCipher($info, substr($keyblock, 0, $keySize), substr($keyblock, 2 * $keySize, $ivSize)) : 
      new TLS12BlockCipher($info, substr($keyblock, 2 * $macSize, $keySize), substr($keyblock, 0, $macSize), $encryptThenMAC);
  }

  public function getServerKey() : Cipher{
    $info = $this->context->getCipherInfo();
    $ivSize = $info->encryption === 'chacha20-poly1305' ? $info->getIVSize() : 4;
    $keySize = $info->getKeySize();
    $macSize = $info->getMacSize();
    $keyblock = $this->keyExpansion;
    $encryptThenMAC = array_key_exists(ExtensionType::ENCRYPT_THEN_MAC->value, $this->context->getClientHello()->extensions);
    
    if($this->keyExpansion === null){
      throw new TLSException("Key expansion must be derived before getting server key");
    }

    return $info->isAEAD() ? 
      new TLS12AEADCipher($info, substr($keyblock, $keySize, $keySize), substr($keyblock, 2 * $keySize + $ivSize, $ivSize)) : 
      new TLS12BlockCipher($info, substr($keyblock, 2 * $macSize + $keySize, $keySize), substr($keyblock, $macSize, $macSize), $encryptThenMAC);
  }

  public static function PRF(string $secret, string $label, string $seed, int $length, CipherInfo $info) : string{
    $result = '';
    $a = "{$label}{$seed}";

    while(strlen($result) < $length){
      $a = hash_hmac($info->mac, $a, $secret, true);
      $result .= hash_hmac($info->mac, "{$a}{$label}{$seed}", $secret, true);
    }

    return substr($result, 0, $length);
  }
}