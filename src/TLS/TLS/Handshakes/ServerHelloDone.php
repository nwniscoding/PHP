<?php
namespace TLS\Handshakes;

use TLS\Enums\HandshakeType;

class ServerHelloDone extends Handshake{
  public function __construct(){
    parent::__construct(HandshakeType::SERVER_HELLO_DONE);
  }

  public function encode(): string{
    return '';
  }

  public static function decode(string $data): static{
    return new self;
  }

  public function jsonSerialize(): array{
    return [
      'type' => $this->type->name,
    ];
  }
}