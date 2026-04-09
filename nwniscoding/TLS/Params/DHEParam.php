<?php
namespace nwniscoding\TLS\Params;

use nwniscoding\IO\BufferReader;
use nwniscoding\IO\BufferWriter;
use function strlen;

final readonly class DHEParam implements Param{
  public ?string $prime;

  public ?string $generator;

  public string $publicKey;

  public function __construct(
    string $publicKey,
    ?string $prime = null,
    ?string $generator = null
  ){
    $this->publicKey = $publicKey;
    $this->prime = $prime;
    $this->generator = $generator;
  }

  public static function decode(BufferReader $reader, int $type) : static{
    if($type == self::CLIENT){
      $publicKey = $reader->read($reader->readUInt16());
    }
    else{
      $prime = $reader->read($reader->readUInt16());
      $generator = $reader->read($reader->readUInt16());
      $publicKey = $reader->read($reader->readUInt16());
    }

    return new self($publicKey, $prime, $generator);
  }

  public function __tostring() : string{
    $writer = new BufferWriter();

    if($this->prime !== null){
      $writer->writeUint16(strlen($this->prime));
      $writer->write($this->prime);
    }

    if($this->generator !== null){
      $writer->writeUint16(strlen($this->generator));
      $writer->write($this->generator);
    }

    $writer->writeUint16(strlen($this->publicKey));
    $writer->write($this->publicKey);

    return $writer->data();
  }
}