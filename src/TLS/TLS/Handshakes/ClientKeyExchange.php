<?php
namespace TLS\Handshakes;

use TLS\Enums\HandshakeType;
use TLS\Utils\BufferReader;

class ClientKeyExchange extends Handshake{
  private array $params = [];

  public function __construct(){
    parent::__construct(HandshakeType::CLIENT_KEY_EXCHANGE);
  }

  public function encode(): string{
    return pack('');
  }

  public static function decode(string $data): static{
    $buffer = new BufferReader($data);
    $handshake = new self;

    
    
    return new self;
  }

  public function jsonSerialize(): array{
    return [
      'type' => $this->type->name,
      'params' => $this->params,
    ];
  }
}