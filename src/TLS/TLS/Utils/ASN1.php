<?php
namespace TLS\Utils;

class ASN1{
  public static function seq(string ...$data): string{
    $data = implode('', $data);

    return pack('Ca*a*', 0x30, self::getLength($data), $data);
  }

  public static function bit(string $data): string{
    $data = "\0" . $data;
    return chr(0x03) . self::getLength($data) . $data;
  }

  public static function getLength(string &$data): string{
    $len = strlen($data);
    
    if($len < 0x80) return chr($len);

    $bytes = '';

    while($len > 0){
      $bytes = chr($len & 0xFF) . $bytes;
      $len >>= 8;
    }

    return chr(0x80 | strlen($bytes)) . $bytes;
  }

  public static function getOIDString(array $oid): string{
    $i = 0;
    $result = chr($oid[$i++] * 40 + $oid[$i++]);

    for(; $i < count($oid); $i++){
      $value = $oid[$i];

      if($value < 128){
        $result .= chr($value);

        continue;
      }

      $bytes = [];

      do{
        $bytes[] = $value & 0x7F;
        $value >>= 7;
      }
      while($value > 0);

      for($j = count($bytes) - 1; $j >= 0; $j--){
        if($j !== 0){
          $bytes[$j] |= 0x80;
        }

        $result .= chr($bytes[$j]);
      }
    }

    return chr(0x06) . self::getLength($result) . $result;
  }
}