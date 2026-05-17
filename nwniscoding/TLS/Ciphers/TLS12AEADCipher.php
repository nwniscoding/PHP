<?php
namespace nwniscoding\TLS\Ciphers;

use function strlen;

use nwniscoding\TLS\Enums\RecordType;
use nwniscoding\TLS\Enums\Version;

final class TLS12AEADCipher implements Cipher{
  private string $key;

  private string $iv;

  private CipherInfo $info;

  public function __construct(CipherInfo $info, string $key, string $iv){
    $this->info = $info;
    $this->key = $key;
    $this->iv = $iv;
  }

  public function encrypt(int $seq, RecordType $type, Version $version, string $text) : string{
    $sequenceBytes = pack('J', $seq);
    $randomBytes = openssl_random_pseudo_bytes(8);

    $enc = $this->info->encryption;
    $iv = $this->iv;
    $key = $this->key;

    if($enc === 'chacha20-poly1305'){
      $paddedSequence = str_pad($sequenceBytes, 12, "\0", STR_PAD_LEFT);
      $nonce = $paddedSequence ^ $iv;
      $randomBytes = '';
    }
    else{
      $nonce = "{$iv}{$randomBytes}";
    }

    $aad = pack('a*Cn2', $sequenceBytes, $type->value, $version->value, strlen($text));

    $ciphertext = openssl_encrypt($text, $enc, $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);

    return "{$randomBytes}{$ciphertext}{$tag}";
  }

  public function decrypt(int $seq, RecordType $type, Version $version, string $data) : string{
    $sequenceBytes = pack('J', $seq);

    $enc = $this->info->encryption;
    $key = $this->key;
    $iv = $this->iv;

    if($enc === 'chacha20-poly1305'){
      $nonce = str_pad($sequenceBytes, 12, "\0", STR_PAD_LEFT) ^ $iv;
      $tag = substr($data, -16);
      $ciphertext = substr($data, 0, -16);
    }
    else{
      $randomBytes = substr($data, 0, 8);
      $ciphertext = substr($data, 8, -16);
      $tag = substr($data, -16);
      $nonce = "{$iv}{$randomBytes}";
    }

    $aad = pack('a*Cn2', $sequenceBytes, $type->value, $version->value, strlen($ciphertext));

    return openssl_decrypt($ciphertext, $enc, $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
  }
}