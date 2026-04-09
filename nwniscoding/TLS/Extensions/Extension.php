<?php
namespace nwniscoding\TLS\Extensions;

use function strlen;

use nwniscoding\IO\BufferReader;
use nwniscoding\IO\BufferWriter;
use nwniscoding\TLS\Enums\ExtensionType;
use nwniscoding\TLS\Sessions\Session;

abstract readonly class Extension{
  abstract public function getType() : ExtensionType;

  abstract protected function encode() : string;

  abstract public static function decode(BufferReader $reader, string $class);

  public function __tostring() : string{
    $writer = new BufferWriter();
    $encode = $this->encode();

    $writer->writeUint16($this->getType()->value);
    $writer->writeUint16(strlen($encode));
    $writer->write($encode);

    return $writer->data();
  }
}