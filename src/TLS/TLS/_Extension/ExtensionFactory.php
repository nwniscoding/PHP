<?php
namespace TLS\Extensions;

use TLS\Enums\ExtensionType;
use TLS\TLSException;

class ExtensionFactory{
  public static function createExtension(int $ext, string $data): Extension{
    $ext = ExtensionType::tryFrom($ext);

    return match($ext){
      ExtensionType::RENEGOTIATION_INFO => RenegotiationInfo::decode($data),
      ExtensionType::EXTENDED_MASTER_SECRET => ExtendedMasterSecret::decode($data),
      ExtensionType::ENCRYPT_THEN_MAC => EncryptThenMAC::decode($data),
      ExtensionType::SESSION_TICKET => SessionTicketExtension::decode($data),
      ExtensionType::SIGNATURE_ALGORITHMS => SignatureAlgorithmExtension::decode($data),
      default => new UnknownExtension($ext, $data),
    };
  }
}