<?php
namespace TLS\Handshakes;

use TLS\Enums\HandshakeType;
use TLS\Utils\BufferReader;

class ClientKeyExchange extends Handshake{
  private string $data;

  public function __construct(string $data = ''){
    parent::__construct(HandshakeType::CLIENT_KEY_EXCHANGE);
    $this->data = $data;
  }

  public function encode(): string{
    return $this->data;
  }

  public static function decode(string $data): static{
    return new self($data);
  }

  public function jsonSerialize(): array{
    return [
      'type' => $this->type->name
    ];
  }
}