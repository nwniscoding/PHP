<?php
namespace nwniscoding\TLS\Handshakes;

use nwniscoding\TLS\Enums\HandshakeEnum;
use nwniscoding\TLS\Utils\Buffer;

class ClientKeyExchange extends Handshake{
  private string $data;

  public function __construct(string $data){
    parent::__construct(HandshakeEnum::CLIENT_KEY_EXCHANGE);
    $this->data = $data;
  }

  public function encode(): string{
    $total = \strlen($this->data) + 2;

    $buffer = new Buffer();
    $buffer->setU8($this->type->value);
    $buffer->setU8(($total >> 16) & 0xFF);
    $buffer->setU8(($total >> 8) & 0xFF);
    $buffer->setU8($total & 0xFF);
    $buffer->setU16(strlen($this->data));
    $buffer->write($this->data);

    return $buffer;
  }

  public static function decode(string $data): self{
    $data = new Buffer($data);
    $length = $data->getU8() << 16 | $data->getU8() << 8 | $data->getU8();
    $text = $data->read($length);

    return new self($text);
  }
}