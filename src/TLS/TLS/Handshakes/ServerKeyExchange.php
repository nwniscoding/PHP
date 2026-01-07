<?php
namespace TLS\Handshakes;

use TLS\Context;
use TLS\Enums\HandshakeType;
use TLS\Utils\BufferReader;
use TLS\Utils\BufferWriter;

final class ServerKeyExchange extends Handshake{
  private ?string $param = null;

  private ?string $identity = null;

  public static function getType(): HandshakeType{
    return HandshakeType::SERVER_KEY_EXCHANGE;
  }

  public function setPSKIdentity(string $identity): self{
    $this->identity = $identity;
    
    return $this;
  }

  public function getPSKIdentity(): ?string{
    return $this->identity;
  }

  public function encode(): BufferWriter{
    return new BufferWriter();
  }

  public static function decode(BufferReader $reader, Context $context): static{
    $handshake = new self($context);

    return $handshake;
  }
}