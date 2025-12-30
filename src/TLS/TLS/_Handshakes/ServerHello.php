<?php
namespace TLS\Handshakes;

use TLS\Enums\CipherEnum;
use TLS\Enums\HandshakeType;
use TLS\Enums\Version;
use TLS\Extensions\ExtensionFactory;
use TLS\Utils\Buffer;

class ServerHello extends Handshake{
  private Version $version;

  private string $random;

  private ?string $session_id;

  private ?CipherEnum $cipher;

  private array $extensions = [];

  public function __construct(Version $version, ?CipherEnum $cipher = null, ?string $session_id = null){
    parent::__construct(HandshakeType::SERVER_HELLO);
    $this->version = $version;
    $this->random = openssl_random_pseudo_bytes(32);
    $this->session_id = $session_id;
    $this->cipher = $cipher;
  }

  public function setVersion(Version $version): void{
    $this->version = $version;
  }

  public function getVersion(): Version{
    return $this->version;
  }

  public function getRandom(): string{
    return $this->random;
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

    $buffer->setU8(0);

    if(\count($this->extensions) > 0){
      $ext_buffer = new Buffer;

      foreach($this->extensions as $extension){
        $ext_buffer->setU16($extension->getType()->value);
        $ext_buffer->setU16(\strlen($extension));
        $ext_buffer->write($extension);
      }

      $buffer->setU16(\strlen($ext_buffer));
      $buffer->write($ext_buffer);
    }
    else{
      $buffer->setU16(0);
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
    $server_hello = new self(Version::TLS_10);

    $type = $data->getU8();
    $length = ($data->getU8() << 16) | ($data->getU8() << 8) | $data->getU8();

    $server_hello->version = Version::from($data->getU16());
    $server_hello->random = $data->read(32);
    $server_hello->session_id = $data->read($data->getU8());
    $server_hello->cipher = CipherEnum::from($data->getU16());

    $data->move(1);

    for($i = 0, $ext_size = $data->getU16(); $i < $ext_size;){
      $e_type = $data->getU16();
      $e_len = $data->getU16();

      $server_hello->extensions[] = ExtensionFactory::createExtension($e_type, $data->read($e_len));
      $i += 4 + $e_len;
    }

    return $server_hello;
  }
}