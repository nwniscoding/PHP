<?php
namespace nwniscoding\TLS\Extensions;

trait EmptyExtensionTrait{
  public function encode(): string{
    return '';
  }

  public static function decode(string $data): self{
    return new self();
  }

  public function getData(): mixed{
    return true;
  }
}