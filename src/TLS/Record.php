<?php
namespace nwniscoding\TLS;

use nwniscoding\TLS\Enums\HandshakeEnum;
use nwniscoding\TLS\Enums\RecordEnum;
use nwniscoding\TLS\Enums\VersionEnum;
use nwniscoding\TLS\Utils\Buffer;
use Stringable;

class Record{
  public function __construct(
    private ?RecordEnum $type = null,
    private ?VersionEnum $version = null,
    private ?Stringable $data = null
  ){}

  public function getType(): ?RecordEnum{
    return $this->type;
  }

  public function setType(?RecordEnum $type): void{
    $this->type = $type;
  }

  public function getVersion(): ?VersionEnum{
    return $this->version;
  }

  public function setVersion(?VersionEnum $version): void{
    $this->version = $version;
  }

  public function getData(): ?Stringable{
    return $this->data;
  }

  public function setData(?Stringable $data): void{
    $this->data = $data;
  }

  public function encode(): string{
    $buffer = new Buffer();
    $buffer->setU8($this->type->value);
    $buffer->setU16($this->version->value);
    $buffer->setU16(\strlen($this->data));
    $buffer->write($this->data);

    return $buffer;
  }

  public static function decode(string $data): array{
    $data = new Buffer($data);
    $arr = [];

    while(!$data->isEOF()){
      $record = new self;

      $record->type = RecordEnum::from($data->getU8());
      $record->version = VersionEnum::from($data->getU16());
      $length = $data->getU16();
      $str = $data->read($length);

      if($record->type === RecordEnum::HANDSHAKE){
        $type = HandshakeEnum::from($str->getU8());
        $record->data = match($type){
          HandshakeEnum::CLIENT_HELLO => Handshakes\ClientHello::decode($str),
          HandshakeEnum::SERVER_HELLO => Handshakes\ServerHello::decode($str),
          HandshakeEnum::SERVER_HELLO_DONE => Handshakes\ServerHelloDone::decode($str),
          default => null
        };
      }

      $arr[] = $record;
    }

    return $arr;
  }
}