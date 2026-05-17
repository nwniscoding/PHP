<?php
namespace nwniscoding\TLS\Handshakes;

use nwniscoding\IO\BufferReader;
use nwniscoding\TLS\Enums\HandshakeType;
use nwniscoding\TLS\Exceptions\LengthMismatchException;
use nwniscoding\TLS\HandshakeContext;

use function strlen;

/**
 * Finished class represents the Finished handshake message in the TLS protocol. 
 */
final readonly class Finished extends Handshake{
  /**
   * The verify data of the Finished handshake message, which is a hash of all previous handshake messages.
   * @var string 
   */
  public string $verifyData;

  /**
   * Constructs a new Finished handshake message.
   * @param string $verifyData The verify data of the Finished handshake message, which is a hash of all previous handshake messages. It must be exactly 12 bytes long.
   * @throws LengthMismatchException If the verify data is not exactly 12 bytes long.
   */
  public function __construct(string $verifyData){
    if (strlen($verifyData) !== 12) {
      throw new LengthMismatchException("Verify data must be exactly 12 bytes long.");
    }

    $this->verifyData = $verifyData;
  }

  /**
   * Get the type of handshake message.
   * @return HandshakeType The type of the handshake message, which is HandshakeType::FINISHED.
   */
  public function getType() : HandshakeType{
    return HandshakeType::FINISHED;
  }

  /**
   * Encode the Finished handshake message to binary format.
   * @return string The binary representation of the Finished handshake message, which is the verify data.
   */
  protected function encode() : string{
    return $this->verifyData;
  }

  /**
   * Decode a Finished handshake message from binary format.
   * @param BufferReader $reader The BufferReader to read the Finished handshake message from.
   * @param HandshakeContext $context The HandshakeContext to use for decoding the handshake message.
   * @return Finished The decoded Finished handshake message.
   * @throws LengthMismatchException If the verify data is not exactly 12 bytes long.
   */
  public static function decode(BufferReader $reader, HandshakeContext $context) : self{
    $verifyData = $reader->readData();
    return new self($verifyData);
  }
}