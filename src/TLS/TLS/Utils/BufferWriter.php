<?php
namespace TLS\Utils;

use Stringable;

/**
 * A flexible BufferWriter class for writing binary data.
 */
class BufferWriter implements Stringable{
  /**
   * The binary data being written.
   * @var string
   */
  private string $data;

  /**
   * The current write offset.
   * @var int
   */
  private int $offset = 0;

  /**
   * Constructor for BufferWriter.
   * @param int|string|null $data_or_size Preallocate size, use string, or empty buffer.
   */
  public function __construct(int|string|null $data_or_size = null){
    if(is_int($data_or_size)){
      $this->data = str_repeat("\0", $data_or_size);
    } 
    else if(is_string($data_or_size)){
      $this->data = $data_or_size;
    } 
    else{
      $this->data = '';
    }
  }

  /**
   * Internal helper to write data at an offset, expanding the buffer if needed.
   */
  private function writeAt(string $bytes, int $off): void{
    $length = strlen($bytes);
    $current_length = strlen($this->data);

    if($off > $current_length){
      $this->data = str_pad($this->data, $off, "\0");
    }

    $this->data = substr_replace($this->data, $bytes, $off, $length);
  }

  /**
   * Set an 8 bit unsigned integer.
   */
  public function setU8(int $value, ?int $offset = null): self{
    $off = $offset ?? $this->offset;
    $this->writeAt(pack('C', $value), $off);

    if($offset === null) $this->offset += 1;

    return $this;
  }

  /**
   * Set a 16 bit unsigned integer(big-endian).
   */
  public function setU16(int $value, ?int $offset = null): self{
    $off = $offset ?? $this->offset;
    $this->writeAt(pack('n', $value), $off);

    if($offset === null) $this->offset += 2;
    
    return $this;
  }

  /**
   * Set a 24 bit unsigned integer(big-endian).
   */
  public function setU24(int $value, ?int $offset = null): self{
    $off = $offset ?? $this->offset;
    $bytes = pack('C3',($value >> 16) & 0xFF,($value >> 8) & 0xFF, $value & 0xFF);
    $this->writeAt($bytes, $off);

    if($offset === null) $this->offset += 3;

    return $this;
  }

  /**
   * Set a 32 bit unsigned integer(big-endian).
   */
  public function setU32(int $value, ?int $offset = null): self{
    $off = $offset ?? $this->offset;
    $this->writeAt(pack('N', $value), $off);

    if($offset === null) $this->offset += 4;

    return $this;
  }

  /**
   * Write arbitrary bytes at the current offset or provided offset.
   */
  public function write(string $bytes, ?int $offset = null): self{
    $off = $offset ?? $this->offset;
    $this->writeAt($bytes, $off);

    if($offset === null) $this->offset += strlen($bytes);

    return $this;
  }

  /**
   * Move the internal offset.
   */
  public function seek(int $offset): self{
    if($offset < 0){
      throw new \OutOfBoundsException("Seek offset cannot be negative");
    }

    $this->offset = $offset;

    return $this;
  }

  public function move(int $length): self{
    $new_offset = $this->offset + $length;
    
    if($new_offset < 0){
      throw new \OutOfBoundsException("Move results in negative offset");
    }

    $this->offset = $new_offset;

    return $this;
  }

  public function getOffset(): int{
    return $this->offset;
  }

  /**
   * Get the full buffer as a string.
   */
  public function getData(): string{
    return $this->data;
  }

  public function __toString(): string{
    return $this->data;
  }
}
