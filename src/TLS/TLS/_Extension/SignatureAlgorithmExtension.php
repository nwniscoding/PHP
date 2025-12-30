<?php
namespace TLS\Extensions;

use TLS\Enums\ExtensionType;
use TLS\Enums\SignatureAlgorithm;
use TLS\Utils\Buffer;

class SignatureAlgorithmExtension extends Extension{
  private array $algorithms = [];

  public function __construct(SignatureAlgorithm ...$algos){
    parent::__construct(ExtensionType::SIGNATURE_ALGORITHMS);
    $this->algorithms = $algos;
  }

  public function encode(): string{
    $buffer = new Buffer;
    
    $buffer->setU16(count($this->algorithms) * 2);
    
    foreach($this->algorithms as $algorithm)
      $buffer->setU16($algorithm->value);

    return $buffer;
  }

  public static function decode(string $data): self{
    $buffer = new Buffer($data);
    $sig_algo = new self;

    for($i = 0, $size = $buffer->getU16(); $i < $size; $i += 2){
      $sig_algo->algorithms[] = SignatureAlgorithm::from($buffer->getU16());
    }

    return $sig_algo;
  }

  public function getData(): mixed{
    return $this->algorithms;
  }
}