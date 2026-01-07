<?php
namespace TLS\Handshakes;

use TLS\Context;
use TLS\Enums\HandshakeType;
use TLS\Utils\BufferReader;

class HandshakeFactory{
  /**
   * @return ?Handshake
   */
  public static function create(HandshakeType $type, BufferReader $reader, Context $context): ?Handshake{
    return match($type){
      HandshakeType::CLIENT_HELLO => ClientHello::decode($reader, $context),
      HandshakeType::SERVER_HELLO => ServerHello::decode($reader, $context),
      HandshakeType::CERTIFICATE => Certificate::decode($reader, $context),
      HandshakeType::SERVER_HELLO_DONE => ServerHelloDone::decode($reader, $context),
      default => null,
    };
  }
}