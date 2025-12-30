<?php
namespace TLS\Handshakes;

use JsonSerializable;
use TLS\Enums\HandshakeType;
use TLS\MessageInterface;

abstract class Handshake implements MessageInterface, JsonSerializable{
  public function __construct(protected HandshakeType $type){}

  public function getType(): HandshakeType{
    return $this->type;
  }

  abstract public function encode(): string;

  abstract public static function decode(string $data): static;

  public function __toString(): string{
    $str = $this->encode();
    return pack('Na*', $this->type->value << 24 | \strlen($str), $str);
  }
}