<?php
namespace TLS\Params;

use Stringable;

abstract class Param implements Stringable{
  abstract public function encode(): string;

  public function __toString(): string{
    return $this->encode();
  }
}