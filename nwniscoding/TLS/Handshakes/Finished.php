<?php
namespace nwniscoding\TLS\Handshakes;

use nwniscoding\IO\BufferReader;
use nwniscoding\TLS\Enums\HandshakeType;
use nwniscoding\TLS\HandshakeContext;

final readonly class Finished extends Handshake{
  public string $verifyData;

  public function __construct(string $verifyData){
    $this->verifyData = $verifyData;
  }

  public function getType() : HandshakeType{
    return HandshakeType::FINISHED;
  }

  protected function encode() : string{
    return $this->verifyData;
  }

  public static function decode(BufferReader $reader, HandshakeContext $context) : self{
    $verifyData = $reader->readData();
    return new self($verifyData);
  }
}