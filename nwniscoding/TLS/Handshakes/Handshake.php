<?php
namespace nwniscoding\TLS\Handshakes;

use nwniscoding\IO\BufferWriter;
use nwniscoding\TLS\HandshakeContext;
use function strlen;

use nwniscoding\IO\BufferReader;
use nwniscoding\TLS\Enums\HandshakeType;

abstract readonly class Handshake{
  abstract public function getType() : HandshakeType;

  abstract protected function encode() : string;

  abstract public static function decode(BufferReader $reader, HandshakeContext $context) : self;

  public function __tostring() : string{
    $data = $this->encode();
    $writer = new BufferWriter();
    $writer->writeUint8($this->getType()->value);
    $writer->writeUint24(strlen($data));
    $writer->write($data);

    return $writer->data();
  }
}