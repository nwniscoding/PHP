<?php
namespace TLS;

use Generator;
use TLS\Enums\HandshakeType;
use TLS\Enums\RecordType;
use TLS\Enums\Version;
use TLS\Handshakes\ClientHello;
use TLS\Handshakes\Handshake;
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

  public function getPayload(): mixed{
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

  public static function parse(string $data): ?Generator{
    $reader = new BufferReader($data);

    while($reader->getOffset() < $reader->getSize()){
      yield self::decode($reader);
    }
  }

  public static function decode(BufferReader $data): static{
    $type = RecordType::from($data->getU8());
    $version = Version::from($data->getU16());
    $length = $data->getU16();

    if($type === RecordType::HANDSHAKE){
      $handshake_type = HandshakeType::from($data->getU8());
      $handshake_length = $data->getU24();
      $handshake_data = $data->read($handshake_length);

      $payload = match($handshake_type){
        HandshakeType::CLIENT_HELLO => ClientHello::decode($handshake_data),
        HandshakeType::SERVER_HELLO => ServerHello::decode($handshake_data),
        // HandshakeType::CERTIFICATE => Certificate::decode($handshake_data),
        // HandshakeType::CLIENT_KEY_EXCHANGE => ClientKeyExchange::decode($handshake_data),
        // HandshakeType::SERVER_KEY_EXCHANGE => ServerKeyExchange::decode($handshake_data),
        HandshakeType::SERVER_HELLO_DONE => ServerHelloDone::decode($handshake_data),
        default => throw new \Exception("Unsupported handshake type: " . $handshake_type->name),
      };
    }
    else{
      $payload = $data->read($length);
    }

    return new self($type, $version, $payload);
  }

}