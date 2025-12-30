<?php
namespace TLS\Extensions;

use TLS\Enums\ExtensionType;

class UnknownExtension extends Extension{
  private string $data;

  public function __construct(ExtensionType $type, string $data){
    parent::__construct($type);
    $this->data = $data;
  }

  public function encode(): string{
    return '';
  }

  public static function decode(string $data): static{
    return new self(ExtensionType::UNKNOWN, $data);
  }

  public function getData(): mixed{
    return $this->data;
  }
}