<?php
namespace TLS\Utils;

use OutOfBoundsException;
use Stringable;

/**
 * A simple BufferReader class for reading binary data.
 */
class BufferReader implements Stringable{
  /**
   * The binary data to read from.
   * @var string
   */
  private readonly string $data;

  /**
   * The size of the binary data.
   * @var int
   */
  private readonly int $size;

  /**
   * The current read offset.
   * @var int
   */
  private int $offset = 0;

  /**
   * The start offset for reading.
   */
  private int $start;

  /**
   * The end offset for reading.
   * @var int
   */
  private int $end;

  public function __construct(string $data, ?int $start = null, ?int $end = null){
    $this->data = $data;
    $this->size = strlen($data);
    $this->start = $start ?? 0;
    $this->end = $end ?? $this->size;
  }

  public function getSize(): int{
    return $this->end - $this->start;
  }

  /**
   * Get the 8 bit unsigned integer at the current offset.
   * @throws OutOfBoundsException
   * @return int
   */
  public function getU8(): int{
    if($this->isOOB(1))
      throw new OutOfBoundsException("Buffer underflow on getU8");

    $this->offset += 1;
    return unpack("C", $this->data, $this->start + $this->offset - 1)[1];
  }

  /**
   * Get the 16 bit unsigned integer at the current offset.
   * @throws OutOfBoundsException
   * @return int
   */
  public function getU16(): int{
    if($this->isOOB(2))
      throw new OutOfBoundsException("Buffer underflow on getU16");

    $this->offset += 2;
    return unpack('n', $this->data, $this->start + $this->offset - 2)[1];
  }

  /**
   * Get the 24 bit unsigned integer at the current offset.
   * @throws OutOfBoundsException
   * @return int
   */
  public function getU24(): int{
    if($this->isOOB(3))
      throw new OutOfBoundsException("Buffer underflow on getU24");

    $this->offset += 3;

    $bytes = unpack('C3', $this->data, $this->start + $this->offset - 3);

    return ($bytes[1] << 16) | ($bytes[2] << 8) | $bytes[3];
  }

  /**
   * Get the 32 bit unsigned integer at the current offset.
   * @throws OutOfBoundsException
   * @return int
   */
  public function getU32(): int{
    if($this->isOOB(4))
      throw new OutOfBoundsException("Buffer underflow on getU32");

    $this->offset += 4;
    return unpack('N', $this->data, $this->start + $this->offset - 4)[1];
  }

  /**
   * Read a specified length of bytes from the current offset.
   * @param int $length
   * @throws OutOfBoundsException
   * @return BufferReader
   */
  public function read(int $length): self{
    if($this->isOOB($length))
      throw new OutOfBoundsException("Buffer underflow on read($length)");

    $offset = $this->start + $this->offset;
    $this->offset += $length;

    return new self($this->data, $offset, $offset + $length);
  }

  /**
   * Check if reading the specified length would go out of bounds.
   * @param int $length
   * @return bool
   */
  private function isOOB(int $length): bool{
    return ($this->offset + $this->start + $length) > $this->end;
  }

  /**
   * Get the original binary data.
   * @return string
   */
  public function getData(): string{
    return $this->data;
  }

  /**
   * Seek to a specific offset in the buffer.
   * @param int $offset
   * @throws OutOfBoundsException
   * @return void
   */
  public function seek(int $offset): void{
    if($offset + $this->start < 0 || $offset + $this->start > $this->end)
      throw new OutOfBoundsException("Seek offset out of bounds");

    $this->offset = $offset;
  }

  public function getOffset(): int{
    return $this->offset;
  }

  /**
   * Move the current offset by a specified length.
   * @param int $length
   * @throws OutOfBoundsException
   * @return void
   */
  public function move(int $length): void{
    if($this->isOOB($length))
      throw new OutOfBoundsException("Move length out of bounds");

    $this->offset += $length;
  }

  public function __tostring(): string{
    return substr($this->data, $this->start, $this->end - $this->start);
  }
}
