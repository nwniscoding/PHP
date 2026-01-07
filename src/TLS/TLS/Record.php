<?php
namespace TLS;

use Generator;
use TLS\Enums\HandshakeType;
use TLS\Enums\RecordType;
use TLS\Enums\Version;
use TLS\Handshakes\Certificate;
use TLS\Handshakes\ClientHello;
use TLS\Handshakes\Handshake;
use TLS\Handshakes\HandshakeFactory;
use TLS\Handshakes\ServerHello;
use TLS\Handshakes\ServerHelloDone;
use TLS\Utils\BufferReader;

class Record{
  private function __construct(
    private RecordType $type,
    private Version $version,
    private mixed $payload
  ){}

  public function getType(): RecordType{
    return $this->type;
  }

  public function getVersion(): Version{
    return $this->version;
  }

  public function getPayload(): string|Handshake{
    return $this->payload;
  }

  public static function changeCipherSpec(Version $version): string{
    return pack(
      'Cn2a*', 
      RecordType::CHANGE_CIPHER->value,
      $version->value,
      1,
      "\x01"
    );
  }

  public static function handshake(Version $version, Handshake | string $handshake): string{
    return pack(
      'Cn2a*', 
      RecordType::HANDSHAKE->value,
      $version->value,
      \strlen($handshake),
      $handshake
    );
  }

  /**
   * @return ?Generator<int, Record>
   */
  public static function parse(string $data, Context $context): ?Generator{
    $reader = new BufferReader($data);

    while($reader->getOffset() < $reader->getSize()){
      yield self::decode($reader, $context);
    }
  }

  public static function decode(BufferReader $data, Context $context): static{
    $type = RecordType::from($data->getU8());
    $version = Version::from($data->getU16());
    $length = $data->getU16();

    if($type === RecordType::HANDSHAKE){
      $handshake_type = HandshakeType::from($data->getU8());
      $handshake_length = $data->getU24();
      $handshake_data = $data->read($handshake_length);

      $payload = HandshakeFactory::create($handshake_type, new BufferReader($handshake_data), $context);
    }
    else{
      $payload = $data->read($length);
    }

    return new self($type, $version, $payload);
  }

}