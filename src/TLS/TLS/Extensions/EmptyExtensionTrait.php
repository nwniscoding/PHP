<?php
namespace TLS\Extensions;

use TLS\Utils\BufferReader;
use TLS\Utils\BufferWriter;

/**
 * Trait for extensions with no data
 */
trait EmptyExtensionTrait{

  public function encode(): BufferWriter{
    return new BufferWriter('');
  }

  public static function decode(BufferReader $data): static{
    return new static();
  }

  public function getData(): mixed{
    return true;
  }
}