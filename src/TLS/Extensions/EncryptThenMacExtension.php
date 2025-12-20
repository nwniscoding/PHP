<?php
namespace nwniscoding\TLS\Extensions;

class EncryptThenMacExtension extends Extension{
  use EmptyExtensionTrait;

  public function __construct(){
    parent::__construct(\nwniscoding\TLS\Enums\ExtensionEnum::ENCRYPT_THEN_MAC);
  }
}