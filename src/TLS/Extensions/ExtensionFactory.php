<?php
namespace nwniscoding\TLS\Extensions;

use InvalidArgumentException;
use nwniscoding\TLS\Enums\ExtensionEnum;

class ExtensionFactory{
  public static function createExtension(int $ext, string $data): Extension{
    $ext = ExtensionEnum::tryFrom($ext);

    if($ext === null) throw new InvalidArgumentException("Unknown extension type: $ext");

    return match($ext){
      ExtensionEnum::RENEGOTIATION_INFO => RenegotiationInfoExtension::decode($data),
      ExtensionEnum::EXTENDED_MASTER_SECRET => ExtendedMasterSecretExtension::decode($data),
      ExtensionEnum::ENCRYPT_THEN_MAC => EncryptThenMacExtension::decode($data),
      ExtensionEnum::SESSION_TICKET => SessionTicketExtension::decode($data),
      ExtensionEnum::SIGNATURE_ALGORITHMS => SignatureAlgorithmExtension::decode($data),
      default => new UnknownExtension($ext, $data),
    };
  }
}