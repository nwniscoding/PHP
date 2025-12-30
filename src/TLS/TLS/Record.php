<?php
namespace TLS;

use Generator;
use JsonSerializable;
use TLS\Enums\HandshakeType;
use TLS\Enums\RecordType;
use TLS\Enums\Version;
use TLS\Handshakes\ClientHello;
use TLS\Handshakes\ServerHello;
use TLS\Utils\BufferReader;

class Record implements MessageInterface, JsonSerializable{
  private RecordType $type;

  private Version $version;

  private MessageInterface | string $data;

  public function __construct(RecordType $type, Version $version, MessageInterface | string $data = ''){
    $this->type = $type;
    $this->version = $version;
    $this->data = $data;
  }

  public function getType(): RecordType{
    return $this->type;
  }

  public function getData(): MessageInterface | string{
    return $this->data;
  }

  public function setData(MessageInterface | string $data): void{
    $this->data = $data;
  }

  public static function parseRecord(string $data): Generator{
    $offset = 0;
    $size = \strlen($data);

    while($offset < $size){
      $record_length = \ord($data[$offset + 3]) << 8 | \ord($data[$offset + 4]);
      $record_data = substr($data, $offset, $record_length + 5);

      yield self::decode($record_data);

      $offset += 5 + $record_length;
    }
  }

  public function encode(): string{
    return pack(
      'Cn2a*',
      $this->type->value,
      $this->version->value,
      \strlen($this->data),
      $this->data
    );
  }

  public static function decode(string $data): static{
    $buffer = new BufferReader($data);
    $record = new static(
      RecordType::from($buffer->getU8()),
      Version::from($buffer->getU16())
    );

    $record_length = $buffer->getU16() + $buffer->getOffset();

    if($record->type === RecordType::HANDSHAKE){
      $handshake = $buffer->getU32();
      $handshake_type = HandshakeType::from($handshake >> 24);
      $handshake_length = $handshake & 0xFFFFFF;

      $record->data = match($handshake_type){
        HandshakeType::CLIENT_HELLO => ClientHello::decode($buffer->read($handshake_length)),
        HandshakeType::SERVER_HELLO => ServerHello::decode($buffer->read($handshake_length)),
        default => "unknown handshake type",
      };
    }

    if($record_length !== $buffer->getSize()){
      throw new TLSException('Record length does not match buffer size');
    }

    return $record;
  }

  public function jsonSerialize(): mixed{
    return [
      'type' => $this->type->name,
      'version' => $this->version->name,
      'data' => $this->data,
    ];
  }

  public function __tostring(): string{
    return $this->encode();
  }
}