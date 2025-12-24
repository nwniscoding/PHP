<?php
namespace nwniscoding\TLS\Handshakes;

use nwniscoding\TLS\Enums\HandshakeEnum;
use nwniscoding\TLS\Utils\Buffer;

class Finished extends Handshake{
  private string $verify_data;

  public function __construct(string $data){
    parent::__construct(HandshakeEnum::FINISHED, $data);
    $this->verify_data = $data;
  }

  public function encode(): string{
    $buffer = new Buffer();
    $buffer->setU32($this->type->value << 24 | \strlen($this->verify_data));
    $buffer->write($this->verify_data);

    return $buffer;
  }

  public static function decode(string $data): self{
    $data = new Buffer($data);
    $type = $data->getU8();
    $length = $data->getU8() << 16 | $data->getU8() << 8 | $data->getU8();

    return new self($data->read($length));
  }

  public function getData(): string{
    return $this->verify_data;
  }
}