<?php
namespace nwniscoding\TLS\Extensions;

use nwniscoding\TLS\Enums\ExtensionEnum;

class UnknownExtension extends Extension{
  private string $data;

  public function __construct(ExtensionEnum $type, string $data){
    parent::__construct($type);
    $this->data = $data;
  }

  public function encode(): string{
    return '';
  }

  public static function decode(string $data): self{
    return new self(ExtensionEnum::UNKNOWN, $data);
  }

  public function getData(): mixed{
    return $this->data;
  }
}