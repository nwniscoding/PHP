<?php
namespace TLS\Handshakes;

use TLS\Enums\HandshakeType;

class ServerHelloDone extends Handshake{
  public function __construct(){
    parent::__construct(HandshakeType::SERVER_HELLO_DONE);
  }

  public function encode(): string{
    return pack('C', $this->type->value) . str_repeat("\0", 3);
  }

  public static function decode(string $data): self{
    return new self();
  }
}