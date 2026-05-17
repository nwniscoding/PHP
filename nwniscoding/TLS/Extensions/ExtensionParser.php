<?php
namespace nwniscoding\TLS\Extensions;


use nwniscoding\IO\BufferReader;
use nwniscoding\TLS\Enums\ExtensionType;
use nwniscoding\TLS\Enums\HandshakeType;
use nwniscoding\TLS\Exceptions\TLSEnumException;

final class ExtensionParser{
  private static array $handlers = [
    ExtensionType::ENCRYPT_THEN_MAC->value => EncryptThenMAC::class,
    ExtensionType::EXTENDED_MASTER_SECRET->value => ExtendedMasterSecret::class,
    ExtensionType::SUPPORTED_GROUPS->value => SupportedGroups::class,
    ExtensionType::SIGNATURE_ALGORITHMS->value => SignatureAlgorithms::class,
    ExtensionType::KEY_SHARE->value => KeyShare::class,
  ];

  public static function parse(BufferReader $reader, int &$length, HandshakeType $hstype) : Extension{
    if($hstype !== HandshakeType::CLIENT_HELLO && $hstype !== HandshakeType::SERVER_HELLO){
      throw new TLSEnumException(HandshakeType::class, $hstype->value, "Extension only allowed in ClientHello and ServerHello");
    }
    
    $type = $reader->readUint16();
    $length = $reader->readUint16();
    $data = $reader->extract($length);
    $class = @self::$handlers[$type];

    return $class ? 
      $class::decode($data, $hstype) : 
      new UnknownExtension($type, $data->readData());
  }
}