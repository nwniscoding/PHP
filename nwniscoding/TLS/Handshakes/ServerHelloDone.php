<?php
namespace nwniscoding\TLS\Handshakes;

use nwniscoding\IO\BufferReader;
use nwniscoding\TLS\Enums\HandshakeType;
use nwniscoding\TLS\HandshakeContext;

final readonly class ServerHelloDone extends Handshake{
  public function getType() : HandshakeType{
    return HandshakeType::SERVER_HELLO_DONE;
  }

  protected function encode() : string{
    return '';
  }

  public static function decode(BufferReader $reader, HandshakeContext $context) : self{
    return new self;
  }
}