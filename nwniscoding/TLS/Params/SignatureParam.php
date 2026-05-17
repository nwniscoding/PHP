<?php
namespace nwniscoding\TLS\Params;

use nwniscoding\TLS\Enums\HandshakeType;
use function strlen;
use LogicException;

use nwniscoding\IO\BufferReader;
use nwniscoding\IO\BufferWriter;
use nwniscoding\TLS\Enums\SignatureAlgorithm;

final readonly class SignatureParam implements Param{
  public string $signature;

  public SignatureAlgorithm $algorithm;

  public function __construct(SignatureAlgorithm $algorithm, string $signature){
    $this->algorithm = $algorithm;
    $this->signature = $signature;
  }

  public static function decode(BufferReader $reader, HandshakeType $type){
    if($type === HandshakeType::CLIENT_KEY_EXCHANGE){
      throw new LogicException("SignatureParam is not expected in client context");
    }

    $algorithm = SignatureAlgorithm::from($reader->readUint16());
    $signature = $reader->read($reader->readUint16());

    return new static($algorithm, $signature);
  }

  public function __tostring() : string{
    $writer = new BufferWriter();

    $writer->writeUint16($this->algorithm->value);
    $writer->writeUint16(strlen($this->signature));
    $writer->write($this->signature);

    return $writer->data();
  }
}