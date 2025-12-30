<?php
namespace TLS\Handshakes;

use TLS\Enums\HandshakeType;
use TLS\MessageInterface;

abstract class Handshake implements MessageInterface{
  public function __construct(protected HandshakeType $type){}

  public function getType(): HandshakeType{
    return $this->type;
  }

  public function __toString(): string{
    return $this->encode();
  }
}