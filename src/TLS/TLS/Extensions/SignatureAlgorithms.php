<?php
namespace TLS\Extensions;

use TLS\Enums\ExtensionType;
use TLS\Enums\SignatureAlgorithm;
use TLS\TLSException;
use TLS\Utils\BufferReader;

class SignatureAlgorithms extends Extension{
  private array $supported_algorithms = [];

  public function __construct(SignatureAlgorithm ...$algorithms){
    parent::__construct(ExtensionType::SIGNATURE_ALGORITHMS);
    $this->supported_algorithms = $algorithms;
  }

  public function encode(): string{
    return pack(
      'n*',
      count($this->supported_algorithms) * 2,
      ...array_map(fn($a) => $a->value, $this->supported_algorithms)
    );
  }

  public static function decode(string $data): static{
    $buffer = new BufferReader($data);
    $length = $buffer->getU16();
    $algorithms = [];
    $offset = 0;
    $length = $buffer->getU16();

    while($offset < $length){
      $algorithms[] = SignatureAlgorithm::tryFrom($buffer->getU16());
      $offset += 2;
    }

    if($offset + $length !== $buffer->getSize())
      throw new TLSException('SupportedGroups extension length mismatch');

    return new self(...$algorithms);
  }

  public function jsonSerialize(): mixed{
    return [
      'type' => $this->getType()->name,
      'algorithms' => array_map(fn($a) => $a->name, $this->supported_algorithms),
    ];
  }
}