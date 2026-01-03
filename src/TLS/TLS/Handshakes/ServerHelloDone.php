<?php
namespace TLS\Handshakes;

use TLS\Context;
use TLS\Enums\HandshakeType;
use TLS\Utils\BufferReader;
use TLS\Utils\BufferWriter;

class ServerHelloDone extends Handshake{
  public static function getType(): HandshakeType{
    return HandshakeType::SERVER_HELLO_DONE;
  }

  public function encode(): BufferWriter{
    return new BufferWriter();
  }
  
  public static function decode(BufferReader $data, Context $context): static{
    return new static($context);
  }

  public function __debugInfo(): array{
    return [
      'type' => $this->getType()
    ];
  }
}