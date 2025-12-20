<?php
namespace nwniscoding\TLS\Handshakes;

use InvalidArgumentException;
use nwniscoding\TLS\Enums\CipherEnum;
use nwniscoding\TLS\Enums\ExtensionEnum;
use nwniscoding\TLS\Enums\HandshakeEnum;
use nwniscoding\TLS\Enums\VersionEnum;
use nwniscoding\TLS\Extensions\Extension;
use nwniscoding\TLS\Extensions\ExtensionFactory;
use nwniscoding\TLS\Utils\Buffer;

class ClientHello extends Handshake{
  private VersionEnum $version;

  private string $random;

  private string $session_id;

  private array $cipher_suites = [];

  private array $extensions = [];

  public function __construct(VersionEnum $version = VersionEnum::TLS_10, ?string $session_id = null){
    parent::__construct(HandshakeEnum::CLIENT_HELLO);

    $this->version = $version;
    $this->session_id = $session_id ?? '';
    $this->random = openssl_random_pseudo_bytes(32);
  }

  public function getVersion(): VersionEnum{
    return $this->version;
  }

  public function setVersion(VersionEnum $version): void{
    $this->version = $version;
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

  public function addCiphers(CipherEnum ...$ciphers): void{
    foreach($ciphers as $cipher){
      if(!in_array($cipher, $this->cipher_suites, true)){
        $this->cipher_suites[] = $cipher;
      }
    }
  }

  public function getCiphers(): array{
    return $this->cipher_suites;
  }

  public function removeCiphers(CipherEnum ...$ciphers): void{
    foreach($ciphers as $cipher){
      $index = array_search($cipher, $this->cipher_suites, true);
      if($index !== false){
        unset($this->cipher_suites[$index]);
      }
    }

    $this->cipher_suites = array_values($this->cipher_suites);
  }

  public function addExtension(Extension ...$extensions): void{
    foreach($extensions as $extension){
      // Ignores unknown extensions
      if($extension->getType() === ExtensionEnum::UNKNOWN){
        continue;
      }
      
      $this->extensions[$extension->getType()->value] = $extension;
    }
  }

  public function getExtensions(): array{
    return array_values($this->extensions);
  }

  public function removeExtension(Extension ...$extensions): void{
    foreach($extensions as $extension){
      unset($this->extensions[$extension->getType()->value]);
    }
  }

  public function encode(): string{
    $buffer = new Buffer();
    $buffer->setU32($this->type->value << 24);
    $buffer->setU16($this->version->value);
    $buffer->write($this->random);
    $buffer->setU8(\strlen($this->session_id));
    $buffer->write($this->session_id);
    $buffer->setU16(\count($this->cipher_suites) * 2);

    foreach($this->cipher_suites as $cipher){
      $buffer->setU16($cipher->value);
    }

    $buffer->setU16(0x0100);

    $ext = new Buffer();

    foreach($this->extensions as $extension){
      $ext_data = $extension->encode();
      $ext->setU16($extension->getType()->value);
      $ext->setU16(\strlen($ext_data));
      $ext->write($ext_data);
    }

    $buffer->setU16($ext->getCursor());
    $buffer->write($ext);

    $buffer->setCursor(1);
    $total = strlen($buffer->getData());

    $buffer->setU8($total >> 16 & 0xFF);
    $buffer->setU8($total >> 8 & 0xFF);
    $buffer->setU8($total & 0xFF);

    return $buffer;
  }

  public static function decode(string $data): self{
    $data = new Buffer($data);
    $client_hello = new self();

    $type = $data->getU8();
    $size = ($data->getU8() << 16) | ($data->getU8() << 8) | $data->getU8();

    $client_hello->version = VersionEnum::from($data->getU16());
    $client_hello->random = $data->read(32);
    $client_hello->session_id = $data->read($data->getU8());

    for($i = 0, $cipher_size = $data->getU16(); $i < $cipher_size; $i += 2){
      $client_hello->cipher_suites[] = CipherEnum::from($data->getU16());
    }

    for($i = 0, $ext_size = $data->getU16(); $i < $ext_size;){
      $e_type = $data->getU16();
      $e_len = $data->getU16();

      $client_hello->extensions[] = ExtensionFactory::createExtension($e_type, $data->read($e_len));
      $i += 4 + $e_len;
    }

    return $client_hello;
  }
}