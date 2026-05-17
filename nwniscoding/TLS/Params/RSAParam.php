<?php
namespace nwniscoding\TLS\Params;

use nwniscoding\TLS\Enums\HandshakeType;
use function strlen;

use nwniscoding\IO\BufferReader;
use nwniscoding\IO\BufferWriter;

final readonly class RSAParam implements Param{
  public string $encryptedPreMasterSecret;

  public function __construct(string $encryptedPreMasterSecret){
    $this->encryptedPreMasterSecret = $encryptedPreMasterSecret;
  }

  public static function decode(BufferReader $reader, HandshakeType $type) : static{
    return new static($reader->read($reader->readUint16()));
  }

  public function __tostring() : string{
    $writer = new BufferWriter();
    $writer->writeUint16(strlen($this->encryptedPreMasterSecret));
    $writer->write($this->encryptedPreMasterSecret);
    return $writer->data();
  }
}