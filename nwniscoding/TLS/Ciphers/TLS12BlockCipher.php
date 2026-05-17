<?php
namespace nwniscoding\TLS\Ciphers;

use InvalidArgumentException;
use nwniscoding\TLS\Enums\RecordType;
use nwniscoding\TLS\Enums\Version;
use nwniscoding\TLS\Record;

final class TLS12BlockCipher implements Cipher{
  private string $key;

  private string $mac;

  private CipherInfo $info;
  
  private bool $encrypt_then_mac;

  public function __construct(CipherInfo $info, string $key, string $mac, bool $encrypt_then_mac = false){
    $this->info = $info;
    $this->key = $key;
    $this->mac = $mac;
    $this->encrypt_then_mac = $encrypt_then_mac;
  }

  public function encrypt(int $seq, RecordType $type, Version $version, string $text) : string{
    $sequenceBytes = pack('J', $seq);

    $enc = $this->info->encryption;
    $hash = $this->info->mac;

    $key = $this->key;
    $mac = $this->mac;

    $iv = openssl_random_pseudo_bytes($this->info->getIVSize());

    if($this->encrypt_then_mac){
      $text = self::pad($text);
      $ciphertext = openssl_encrypt($text, $enc, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
      $hmac = hash_hmac($hash, $sequenceBytes . new Record($version, $type, "{$iv}{$ciphertext}"), $mac, true);

      $ciphertext .= $hmac;
    }
    else{
      $hmac = hash_hmac($hash, $sequenceBytes . new Record($version, $type, $text)->toBinary(), $mac, true);
      $text .= $hmac;
      $text = self::pad($text);
      $ciphertext = openssl_encrypt($text, $enc, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
    }

    return "{$iv}{$ciphertext}";
  }

  public function decrypt(int $seq, RecordType $type, Version $version, string $ciphertext) : string{
    $sequenceBytes = pack('J', $seq);

    $enc = $this->info->encryption;
    $hash = $this->info->mac;
    $key = $this->key;
    $mac = $this->mac;

    $iv = substr($ciphertext, 0, $this->info->getIVSize());
    $ciphertext = substr($ciphertext, $this->info->getIVSize());

    if($this->encrypt_then_mac){
      $hmac = substr($ciphertext, -$this->info->getMACSize());
      $ciphertext = substr($ciphertext, 0, -$this->info->getMACSize());
      $calculatedHmac = hash_hmac($hash, $sequenceBytes . (new Record($version, $type, "{$iv}{$ciphertext}"))->toBinary(), $mac, true);
      $text = openssl_decrypt($ciphertext, $enc, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
      $text = self::unpad($text);
    }
    else{
      $text = openssl_decrypt($ciphertext, $enc, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
      $text = self::unpad($text);
      $hmac = substr($text, -$this->info->getMACSize());
      $text = substr($text, 0, -$this->info->getMACSize());
      $calculatedHmac = hash_hmac($hash, $sequenceBytes . (new Record($version, $type, $text))->toBinary(), $mac, true);
    }

    if(!hash_equals($hmac, $calculatedHmac)){
      throw new InvalidArgumentException("Invalid MAC");
    }

    return $text;
  }

  private static function pad(string $data, int $block_size = 16) : string{
    if($block_size < 1){
      throw new InvalidArgumentException("Block size must be a positive integer");
    }

    $padding_length = $block_size - (strlen($data) + 1) % $block_size;
    return $data . str_repeat(chr($padding_length), $padding_length + 1);
  }

  private static function unpad(string $data, int $block_size = 16) : string{
    $padding_length = ord($data[-1]);

    if($padding_length > $block_size){
      throw new InvalidArgumentException("Invalid padding length");
    }

    for($i = 0; $i <= $padding_length; $i++){
      if(ord($data[-1 - $i]) !== $padding_length){
        throw new InvalidArgumentException("Invalid padding");
      }
    }

    return substr($data, 0, -($padding_length + 1));
  }
}