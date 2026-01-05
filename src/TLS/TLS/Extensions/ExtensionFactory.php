<?php
namespace TLS\Extensions;

use TLS\Enums\ExtensionType;
use TLS\TLSException;
use TLS\Utils\BufferReader;

class ExtensionFactory{
  public static function loadExtension(int $ext, BufferReader $data): Extension{
    $ext = ExtensionType::tryFrom($ext);

    return match($ext){
      ExtensionType::RENEGOTIATION_INFO => RenegotiationInfo::decode($data),
      ExtensionType::ENCRYPT_THEN_MAC => EncryptThenMAC::decode($data),
      ExtensionType::SUPPORTED_GROUPS => SupportedGroups::decode($data),
      ExtensionType::SIGNATURE_ALGORITHMS => SignatureAlgorithms::decode($data),
      ExtensionType::EXTENDED_MASTER_SECRET => ExtendedMasterSecret::decode($data),
      default => new UnknownExtension($ext, $data),
    };
  }
}