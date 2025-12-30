<?php
namespace TLS\Extensions;

use TLS\Enums\ExtensionType;

class EncryptThenMAC extends Extension{
  use EmptyExtensionTrait;

  public function __construct(){
    parent::__construct(ExtensionType::ENCRYPT_THEN_MAC);
  }

  public function jsonSerialize(): mixed{
    return [
      'type' => $this->type->name,
      'data' => true,
    ];
  }
}