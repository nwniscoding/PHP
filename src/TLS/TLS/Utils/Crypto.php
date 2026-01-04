<?php
namespace TLS\Utils;

use TLS\Enums\CipherSuite;
use TLS\Record;

final class Crypto{
  public static function PRF(CipherSuite $cipher, string $secret, string $label, string $data, int $length): string{
    $seed = "$label$data";
    $a = $seed;
    $output = '';
    $metadata = $cipher->metadata();

    while(strlen($output) < $length){
      $a = hash_hmac($metadata['hash'], $a, $secret, true);
      $output .= hash_hmac($metadata['hash'], "$a$seed", $secret, true);
    }

    return substr($output, 0, $length);
  }

  public static function HMACRecord(CipherSuite $cipher, int $seq, string $mac, string $data): string{
    $metadata = $cipher->metadata();

    return hash_hmac(
      $metadata['hash'],
      pack('Ja*', $seq, $data),
      $mac,
      true
    );
  }

  public static function generateKey(CipherSuite $cipher, string $master_secret, string $client_random, string $server_random, int $length = 128): array{
    $metadata = $cipher->metadata();

    $seed = "$server_random$client_random";
    $metadata = $cipher->metadata();

    $key_block = self::PRF(
      $cipher, 
      $master_secret, 
      'key expansion', 
      $seed, 
      $length
    );

    $key_size = match($metadata['encryption']){
      'AES-128-CBC', 'AES-128-GCM' => 16,
      'AES-256-CBC', 'AES-256-GCM' => 32,
      default => 16
    };

    if(str_contains($metadata['encryption'], 'GCM')){
      return [
        'client' => [
          'key' => substr($key_block, 0, $key_size),
          'iv' => substr($key_block, $key_size * 2, 4),
        ],
        'server' => [
          'key' => substr($key_block, $key_size, $key_size),
          'iv' => substr($key_block, $key_size * 2 + 4, 4)
        ]
      ];
    }
    else{
      $mac_size = match($metadata['hash']){
        'SHA256' => 32,
        'SHA384' => 48,
        default => 20
      };

      return [
        'client' => [
          'mac' => substr($key_block, 0, $mac_size),
          'key' => substr($key_block, $mac_size * 2, $key_size)
        ],
        'server' => [
          'mac' => substr($key_block, $mac_size, $mac_size),
          'key' => substr($key_block, $mac_size * 2 + $key_size, $key_size)
        ]
      ];
    }
  }

  public static function pad(string $data, int $block_size): string{
    $pad_len = $block_size - (strlen(string: $data) + 1) % $block_size;
    return $data . str_repeat(chr($pad_len), $pad_len + 1);
  }
}