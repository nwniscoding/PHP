<?php
namespace TLS\Extensions;

use TLS\Enums\ExtensionType;
use TLS\MessageInterface;

abstract class Extension implements MessageInterface{
  public function __construct(protected readonly ExtensionType $type){}

  public function getType(): ExtensionType{
    return $this->type;
  }

  abstract public function encode(): string;
  
  abstract public function getData(): mixed;

  public function __tostring(): string{
    return $this->encode();
  }
}