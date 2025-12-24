<?php
namespace nwniscoding\TLS\Handshakes;

use nwniscoding\TLS\Enums\HandshakeEnum;
use Stringable;

abstract class Handshake implements Stringable{
  public function __construct(protected HandshakeEnum $type){}

  public function getType(): HandshakeEnum{
    return $this->type;
  }

  abstract public function encode(): string;

  abstract public static function decode(string $data): self;

  public function __toString(): string{
    return $this->encode();
  }
}