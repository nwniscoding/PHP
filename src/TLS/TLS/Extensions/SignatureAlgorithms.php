<?php
namespace TLS\Extensions;

use TLS\Enums\ExtensionType;
use TLS\Enums\SignatureAlgorithm;
use TLS\TLSException;
use TLS\Utils\BufferReader;
use TLS\Utils\BufferWriter;

class SignatureAlgorithms extends Extension{
  private array $supported_algorithms = [];

  public function __construct(SignatureAlgorithm ...$algorithms){
    parent::__construct(ExtensionType::SIGNATURE_ALGORITHMS);
    $this->supported_algorithms = $algorithms;
  }

  public function encode(): BufferWriter{
    $writer = new BufferWriter;
    $writer->setU16(count($this->supported_algorithms) * 2);

    foreach($this->supported_algorithms as $algorithm){
      $writer->setU16($algorithm->value);
    }

    return $writer;
  }

  public static function decode(BufferReader $reader): static{
    $length = $reader->getU16();
    $algorithms = [];
    $offset = 0;

    while($offset < $length){
      $algorithms[] = SignatureAlgorithm::tryFrom($reader->getU16());
      $offset += 2;
    }

    return new self(...$algorithms);
  }
}