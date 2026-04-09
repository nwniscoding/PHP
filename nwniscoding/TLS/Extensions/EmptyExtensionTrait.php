<?php
namespace nwniscoding\TLS\Extensions;

use nwniscoding\IO\BufferReader;
use nwniscoding\TLS\Sessions\Session;

trait EmptyExtensionTrait{
  protected function encode() : string{
    return '';
  }
  
  public static function decode(BufferReader $reader, string $class) : Extension{
    return new static();
  }
}