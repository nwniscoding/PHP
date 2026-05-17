<?php
namespace nwniscoding\TLS\Extensions;

use nwniscoding\TLS\Enums\HandshakeType;
use nwniscoding\TLS\Exceptions\TLSEnumException;
use function strlen;

use nwniscoding\IO\BufferReader;
use nwniscoding\IO\BufferWriter;
use nwniscoding\TLS\Enums\ExtensionType;

abstract readonly class Extension{
  abstract public function getType() : ExtensionType;

  abstract protected function encode(HandshakeType $type) : string;

  abstract public static function decode(BufferReader $reader, HandshakeType $type) : self;

  public function toBinary(HandshakeType $type) : string{
    $writer = new BufferWriter();
    $encode = $this->encode($type);

    $writer->writeUint16($this->getType()->value);
    $writer->writeUint16(strlen($encode));
    $writer->write($encode);
    
    return $writer->data();
  }

  protected static function helloCheck(HandshakeType $type) : void{
    if($type !== HandshakeType::CLIENT_HELLO && $type !== HandshakeType::SERVER_HELLO){
      throw new TLSEnumException(HandshakeType::class, $type->value, "Extension only allowed in ClientHello and ServerHello");
    }
  }
}