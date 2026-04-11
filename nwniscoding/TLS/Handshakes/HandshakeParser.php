<?php
namespace nwniscoding\TLS\Handshakes;

use nwniscoding\IO\BufferReader;
use nwniscoding\TLS\Enums\HandshakeType;
use nwniscoding\TLS\HandshakeContext;
use UnexpectedValueException;

final class HandshakeParser{
  public static function parse(BufferReader $reader, HandshakeContext $context) : Handshake{
    $type = $reader->readUint8();
    $length = $reader->readUint24();
    $data = $reader->extract($length);

    return match($type){
      HandshakeType::CLIENT_HELLO->value => ClientHello::decode($data, $context),
      HandshakeType::SERVER_HELLO->value => ServerHello::decode($data, $context),
      HandshakeType::CERTIFICATE->value => Certificate::decode($data, $context),
      HandshakeType::SERVER_HELLO_DONE->value => ServerHelloDone::decode($data, $context),
      HandshakeType::FINISHED->value => Finished::decode($data, $context),
      HandshakeType::SERVER_KEY_EXCHANGE->value => ServerKeyExchange::decode($data, $context),
      default => throw new UnexpectedValueException("Unknown handshake type: $type")
    };
  }
}