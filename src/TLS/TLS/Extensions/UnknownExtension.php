<?php
namespace TLS\Extensions;

use TLS\Enums\ExtensionType;
use TLS\Utils\BufferReader;
use TLS\Utils\BufferWriter;

class UnknownExtension extends Extension{
  private string $data;

  public function __construct(ExtensionType $type, string $data){
    parent::__construct($type);
    $this->data = $data;
  }

  public function encode(): BufferWriter{
    return new BufferWriter($this->data);
  }

  public static function decode(BufferReader $data): static{
    return new self(ExtensionType::UNKNOWN, $data);
  }

  public function getData(): mixed{
    return $this->data;
  }
}