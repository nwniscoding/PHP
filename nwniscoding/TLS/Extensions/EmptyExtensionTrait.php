<?php
namespace nwniscoding\TLS\Extensions;

use nwniscoding\IO\BufferReader;
use nwniscoding\TLS\Enums\HandshakeType;

trait EmptyExtensionTrait{
  protected function encode(HandshakeType $type) : string{
    self::helloCheck($type);
    return '';
  }
  
  public static function decode(BufferReader $reader, HandshakeType $type) : Extension{
    self::helloCheck($type);
    return new static();
  }
}