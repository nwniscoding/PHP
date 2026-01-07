<?php
namespace TLS\Handshakes;

use TLS\Context;
use TLS\Enums\CipherSuite;
use TLS\Enums\HandshakeType;
use TLS\Utils\BufferReader;
use TLS\Utils\BufferWriter;
use TLS\Utils\Crypto;

final class Finished extends Handshake{
  private string $verify_data;

  public function setVerifyData(string $data): self{
    $this->verify_data = $data;

    return $this;
  }

  public function getVerifyData(): string{
    return $this->verify_data;
  }

  public function createMAC(CipherSuite $cipher_suite, string $master_secret, string $type, array $handshakes): self{
    $metadata = $cipher_suite->metadata();

    $this->verify_data = Crypto::PRF(
      $cipher_suite,
      $master_secret,
      "$type finished",
      hash($metadata['hash'], join('', $handshakes), true),
      12
    );

    return $this;
  }

  public static function getType(): HandshakeType{
    return HandshakeType::FINISHED;
  }

  public function encode(): BufferWriter{
    $writer = new BufferWriter;
    $writer->write($this->verify_data);

    return $writer;
  }

  public static function decode(BufferReader $reader, Context $context): static{
    $handshake = new self($context);
    $handshake->verify_data = $reader->read(12);

    return $handshake;
  }
}