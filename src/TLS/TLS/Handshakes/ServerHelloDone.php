<?php
namespace TLS\Handshakes;

use TLS\Context;
use TLS\Enums\HandshakeType;
use TLS\Utils\BufferReader;
use TLS\Utils\BufferWriter;

final class ServerHelloDone extends Handshake{
  public static function getType(): HandshakeType{
    return HandshakeType::SERVER_HELLO_DONE;
  }

  public function encode(): BufferWriter{
    return new BufferWriter;
  }

  public static function decode(BufferReader $reader, Context $context): static{
    $handshake = new self($context);

    return $handshake;
  }
}