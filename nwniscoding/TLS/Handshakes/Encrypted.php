<?php
namespace nwniscoding\TLS\Handshakes;

use nwniscoding\IO\BufferReader;
use nwniscoding\TLS\Enums\HandshakeType;
use nwniscoding\TLS\HandshakeContext;

/**
 * Encrypted class represents a handshake message that is encrypted by the client or server cipher. 
 */
final readonly class Encrypted extends Handshake{
  /**
   * The encrypted content of the handshake message.
   */
  public string $content;

  /**
   * Constructs a new Encrypted handshake message.
   * @param string $content The encrypted content of the handshake message.
   */
  public function __construct(string $content){
    $this->content = $content;
  }

  /**
   * Get the type of handshake message.
   * @return HandshakeType The type of the handshake message, which is HandshakeType::ENCRYPTED.
   */
  public function getType() : HandshakeType{
    return HandshakeType::ENCRYPTED;
  }

  /**
   * Encode the encrypted handshake message to binary format. 
   * @return string The binary representation of the encrypted handshake message.
   */
  protected function encode() : string{
    return $this->content;
  }

  /**
   * Decode an encrypted handshake message from binary format.
   * @param BufferReader $reader The BufferReader to read the encrypted handshake message from.
   * @param HandshakeContext $context The HandshakeContext to use for decoding the handshake message.
   * @return Encrypted The decoded Encrypted handshake message.
   */
  public static function decode(BufferReader $reader, HandshakeContext $context) : self{
    return new self($reader->readData());
  }
}