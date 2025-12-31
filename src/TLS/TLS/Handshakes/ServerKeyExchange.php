<?php
namespace TLS\Handshakes;

use Exception;
use TLS\Enums\HandshakeType;
use TLS\Enums\SupportedGroup;
use TLS\TLSException;
use TLS\Utils\BufferReader;

class ServerKeyExchange extends Handshake{
  private string $data;

  public function __construct(string $data = ''){
    parent::__construct(HandshakeType::SERVER_KEY_EXCHANGE);
    $this->data = $data;
  }

  public function encode(): string{
    return $this->data;
  }

  public static function decode(string $data): static{
    return new self($data);
  }

  public function jsonSerialize(): mixed{
    return [
      'type' => $this->type->name,
    ];
  }
}