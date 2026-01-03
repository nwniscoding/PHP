<?php
namespace TLS\Extensions;

use JsonSerializable;
use TLS\Enums\ExtensionType;
use TLS\MessageInterface;
use TLS\Utils\BufferReader;
use TLS\Utils\BufferWriter;

abstract class Extension{
  public function __construct(protected readonly ExtensionType $type){}

  public function getType(): ExtensionType{
    return $this->type;
  }

  abstract public function encode(): BufferWriter;

  abstract public static function decode(BufferReader $data): static;

  public function __tostring(): string{
    $data = $this->encode();
    $writer = new BufferWriter;

    $writer->setU16($this->type->value);
    $writer->setU16(strlen($data));
    $writer->write($data);

    return (string) $writer;
  }

  public function __debugInfo(): ?array{
    return [
      'type' => $this->getType()->name,
    ];
  }
}