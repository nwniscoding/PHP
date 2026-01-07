<?php
namespace TLS\Crypto;

use TLS\Enums\CipherSuite;

class AEADCipher{
  private string $enc_key;

  private string $iv_key;

  public function __construct(
    private string $type,
    private CipherSuite $cipher,
    string $key_block
  ){
    $this->parse($key_block);
  }

  public function getWriteKey(): string{
    return $this->enc_key;
  }

  public function getMACKey(): string{
    return '';
  }

  private function parse(string $block): void{
    $cipher = $this->cipher;
    $type = $this->type;
    $key_size = openssl_cipher_key_length($cipher->name);
    $iv_size = 12;
    $this->enc_key = substr($block, $key_size * ($type === 'server'), $key_size);
    $this->iv_key = substr($block, $key_size * 2 + ($type === 'server') * $iv_size, $iv_size);
  }

}