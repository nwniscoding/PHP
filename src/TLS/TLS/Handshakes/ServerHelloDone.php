<?php
namespace TLS\Handshakes;

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

  public static function decode(BufferReader $reader): static{
    $handshake = new self;

    return $handshake;
  }
}