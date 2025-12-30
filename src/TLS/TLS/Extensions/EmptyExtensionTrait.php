<?php
namespace TLS\Extensions;

/**
 * Trait for extensions with no data
 */
trait EmptyExtensionTrait{
  public function encode(): string{
    return '';
  }

  public static function decode(string $data): static{
    return new static();
  }

  public function getData(): mixed{
    return true;
  }
}