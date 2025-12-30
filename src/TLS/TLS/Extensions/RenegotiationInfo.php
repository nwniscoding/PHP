<?php
namespace TLS\Extensions;

use TLS\Enums\ExtensionType;

class RenegotiationInfo extends Extension{
  use EmptyExtensionTrait;
  
  public function __construct(){
    parent::__construct(ExtensionType::RENEGOTIATION_INFO);
  }

  public function encode(): string{
    return "\0";
  }

  public function jsonSerialize(): mixed{
    return [
      'type' => $this->getType()->name,
      'data' => true,
    ];
  }
}