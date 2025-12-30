<?php
namespace TLS\Extensions;

use JsonSerializable;
use TLS\Enums\ExtensionType;
use TLS\MessageInterface;

abstract class Extension implements MessageInterface, JsonSerializable{
  public function __construct(protected readonly ExtensionType $type){}

  public function getType(): ExtensionType{
    return $this->type;
  }

  public function jsonSerialize(): mixed{
    return [
      'type' => $this->type->name,
    ];
  }

  public function __tostring(): string{
    $str = $this->encode();
    return pack('n2a*', $this->type->value, \strlen($str), $str);
  }
}