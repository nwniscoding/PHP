<?php
namespace nwniscoding\TLS\Handshakes;

use nwniscoding\TLS\Enums\CipherEnum;
use nwniscoding\TLS\Enums\VersionEnum;
use nwniscoding\TLS\Extensions\ExtensionFactory;
use nwniscoding\TLS\Utils\Buffer;

class ServerHello extends Handshake{
  private VersionEnum $version;

  private string $random;

  private ?string $session_id;

  private ?CipherEnum $cipher;

  private array $extensions = [];

  public function __construct(VersionEnum $version, ?CipherEnum $cipher = null, ?string $session_id = null){
    $this->version = $version;
    $this->random = openssl_random_pseudo_bytes(32);
    $this->session_id = $session_id;
    $this->cipher = $cipher;
  }

  public function setVersion(VersionEnum $version): void{
    $this->version = $version;
  }

  public function getVersion(): VersionEnum{
    return $this->version;
  }

  public function setSessionID(string $session_id): void{
    $this->session_id = $session_id;
  }

  public function getSessionID(): ?string{
    return $this->session_id;
  }

  public function setCipher(?CipherEnum $cipher): void{
    $this->cipher = $cipher;
  }

  public function getCipher(): ?CipherEnum{
    return $this->cipher;
  }

  public function encode(): string{
    $buffer = new Buffer();
    $buffer->setU32($this->type->value << 24);
    $buffer->setU16($this->version->value);
    $buffer->write($this->random);
    $buffer->setU8(\strlen($this->session_id ?? ''));

    if($this->session_id !== null)
      $buffer->write($this->session_id);

    if($this->cipher === null)
      throw new \InvalidArgumentException('Cipher must be set before encoding ServerHello');

    $buffer->setU16($this->cipher->value);

    $buffer->setU16(1 << 8);

    if(\count($this->extensions) > 0){
      foreach($this->extensions as $extension){
        $buffer->setU16($extension->getType()->value);
        $buffer->setU16(\strlen($extension));
        $buffer->write($extension);
      }
    }

    $total = \strlen($buffer->getData()) - 4;
    
    $buffer->setCursor(1);
    $buffer->setU8($total >> 16 & 0xFF);
    $buffer->setU8($total >> 8 & 0xFF);
    $buffer->setU8($total & 0xFF);

    return $buffer;
  }

  public static function decode(string $data): self{
    $data = new Buffer($data);
    $server_hello = new self(VersionEnum::TLS_10);

    $type = $data->getU8();
    $length = ($data->getU8() << 16) | ($data->getU8() << 8) | $data->getU8();

    $server_hello->version = VersionEnum::from($data->getU16());
    $server_hello->random = $data->read(32);
    $server_hello->session_id = $data->read($data->getU8());
    $server_hello->cipher = CipherEnum::from($data->getU16());

    $data->move(2);

    for($i = 0, $ext_size = $data->getU16(); $i < $ext_size;){
      $e_type = $data->getU16();
      $e_len = $data->getU16();

      $server_hello->extensions[] = ExtensionFactory::createExtension($e_type, $data->read($e_len));
      $i += 4 + $e_len;
    }

    return $server_hello;
  }
}