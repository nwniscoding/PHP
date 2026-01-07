<?php
namespace TLS\Crypto;

use TLS\Enums\CipherSuite;

class BlockCipher{
  private string $mac_key;

  private string $enc_key;

  public function __construct(
    private string $type,
    private CipherSuite $cipher,
    string $key_block
  ){
    $this->parse($key_block);
  }

  public function getMACKey(): string{
    return $this->mac_key;
  }
  
  public function getWriteKey(): string{
    return $this->enc_key;
  }

  private function parse(string $block): void{
    $cipher = $this->cipher;
    $type = $this->type;
    $key_size = openssl_cipher_key_length(str_replace('_', '-', $cipher->getEncryption()));
    $mac_size = match($cipher->getHash()){
      'SHA' => 20,
      'SHA256' => 32,
      'SHA384' => 48
    };
    
    $this->mac_key = substr($block, ($type === 'server') * $mac_size, $mac_size);
    $this->enc_key = substr($block, $mac_size * 2 + ($type === 'server') * $key_size, $key_size);
  }
}