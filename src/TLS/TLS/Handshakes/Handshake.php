<?php
namespace TLS\Handshakes;

use Stringable;
use TLS\Context;
use TLS\Enums\HandshakeType;
use TLS\Utils\BufferReader;
use TLS\Utils\BufferWriter;

abstract class Handshake implements Stringable{
  public function __construct(protected Context $context){}
  
  abstract public function encode(): BufferWriter;

  abstract public static function decode(BufferReader $reader, Context $context): static;

  abstract public static function getType(): HandshakeType;

  public function __tostring(): string{
    $writer = new BufferWriter();
    $str = $this->encode();

    return (string) $writer
    ->setU8($this->getType()->value)
    ->setU24(strlen($str))
    ->write($str);
  }
}