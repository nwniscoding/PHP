<?php
namespace nwniscoding\TLS\Extensions;

use nwniscoding\TLS\Enums\ExtensionEnum;

class SessionTicketExtension extends Extension{
  use EmptyExtensionTrait;

  public function __construct(){
    parent::__construct(ExtensionEnum::SESSION_TICKET);
  }
}