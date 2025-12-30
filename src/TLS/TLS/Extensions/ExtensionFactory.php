<?php
namespace TLS\Extensions;

use TLS\Enums\ExtensionType;
use TLS\TLSException;

class ExtensionFactory{
  public static function loadExtension(int $ext, string $data): Extension{
    $ext = ExtensionType::tryFrom($ext);

    return match($ext){
      ExtensionType::RENEGOTIATION_INFO => RenegotiationInfo::decode($data),
      ExtensionType::ENCRYPT_THEN_MAC => EncryptThenMAC::decode($data),
      ExtensionType::SUPPORTED_GROUPS => SupportedGroups::decode($data),
      default => new UnknownExtension($ext, $data),
    };
  }
}