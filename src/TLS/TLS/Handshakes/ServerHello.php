<?php
namespace TLS\Handshakes;

use TLS\Enums\CipherSuite;
use TLS\Enums\HandshakeType;
use TLS\Enums\Version;
use TLS\Extensions\ExtensionFactory;
use TLS\Utils\BufferReader;

class ServerHello extends Handshake{
  private Version $version;

  private string $random;

  private string $session_id;

  private CipherSuite $cipher_suite;

  private array $extensions = [];

  public function __construct(){
    parent::__construct(HandshakeType::SERVER_HELLO);

    $this->random = openssl_random_pseudo_bytes(32);
  }

  public function encode(): string{
    $extensions = join('', $this->extensions);

    return pack(
      'na*Ca*nC',
      $this->version->value,
      $this->random,
      \strlen($this->session_id),
      $this->session_id,
      $this->cipher_suite->value,
      0
    ).($extensions === '' ? '' : pack('na*', \strlen($extensions), $extensions));
  }

  public static function decode(string $data): static{
    $buffer = new BufferReader($data);
    $handshake = new static();

    $handshake->version = Version::from($buffer->getU16());
    $handshake->random = $buffer->read(32);
    $handshake->session_id = $buffer->read($buffer->getU8());
    $handshake->cipher_suite = CipherSuite::from($buffer->getU16());

    $buffer->getU16(); // compression methods

    if($buffer->isEOF()) return $handshake;

    $ext_size = $buffer->getU8();

    while(!$buffer->isEOF()){
      $extension_type = $buffer->getU16();

      $handshake->extensions[$extension_type] = ExtensionFactory::loadExtension(
        $extension_type,
        $buffer->read($buffer->getU16())
      );
    }

    return $handshake;
  }

  public function jsonSerialize(): mixed{
    return [
      'type' => $this->type->name,
      'version' => $this->version->name,
      'random' => bin2hex($this->random),
      'session_id' => bin2hex($this->session_id),
      'cipher_suite' => $this->cipher_suite->name,
      'extensions' => $this->extensions,
    ];
  }

  public function __debugInfo(): array{
    return [
      'type' => $this->type,
      'version' => $this->version,
      'random' => bin2hex($this->random),
      'session_id' => bin2hex($this->session_id),
      'cipher_suite' => $this->cipher_suite,
      'extensions' => $this->extensions,
    ];
  }
}