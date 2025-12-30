<?php
namespace TLS\Extensions;

use TLS\Enums\ExtensionType;

class EncryptThenMAC extends Extension{
  use EmptyExtensionTrait;

  public function __construct(){
    parent::__construct(ExtensionType::ENCRYPT_THEN_MAC);
  }
}