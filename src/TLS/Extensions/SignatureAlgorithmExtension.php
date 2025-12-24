<?php
namespace nwniscoding\TLS\Extensions;

use nwniscoding\TLS\Enums\ExtensionEnum;
use nwniscoding\TLS\Enums\SignatureAlgorithmEnum;
use nwniscoding\TLS\Utils\Buffer;

class SignatureAlgorithmExtension extends Extension{
  private array $algorithms = [];

  public function __construct(SignatureAlgorithmEnum ...$algos){
    parent::__construct(ExtensionEnum::SIGNATURE_ALGORITHMS);
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
      $sig_algo->algorithms[] = SignatureAlgorithmEnum::from($buffer->getU16());
    }

    return $sig_algo;
  }

  public function getData(): mixed{
    return $this->algorithms;
  }
}