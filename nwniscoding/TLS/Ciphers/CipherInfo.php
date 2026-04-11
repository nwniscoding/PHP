<?php
namespace nwniscoding\TLS\Ciphers;

final readonly class CipherInfo{
  public string $keyExchange;

  public ?string $authentication;
  
  public string $encryption;

  public string $mac;

  public function __construct(string $keyExchange, ?string $authentication, string $encryption, string $mac){
    $this->keyExchange = strtolower($keyExchange);
    $this->authentication = strtolower($authentication ?? '');
    $this->encryption = strtolower($encryption);
    $this->mac = strtolower($mac);
  }

  public function isAEAD() : bool{
    return str_contains($this->encryption, 'gcm') || str_contains($this->encryption, 'ccm') || str_contains($this->encryption, 'chacha20');
  }

  public function getIVSize() : int{
    return openssl_cipher_iv_length($this->encryption);
  }

  public function getKeySize() : int{
    return openssl_cipher_key_length($this->encryption);
  }

  public function getMACSize() : int{
    return match($this->mac){
      'sha', 'sha1' => 20,
      'sha224' => 28,
      'sha256' => 32,
      'sha384' => 48,
      'sha512' => 64,
    };
  }
}