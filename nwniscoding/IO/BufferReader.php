<?php
namespace nwniscoding\IO;

use InvalidArgumentException;
use OutOfBoundsException;
use function strlen;

/**
 * BufferReader is a utility class for reading binary data from a string buffer.
 */
final class BufferReader extends Reader{
  /**
   * The binary data buffer to read from
   * @var string
   */
  private string $buffer;

  /**
   * Current offset in the buffer
   * @var int
   */
  private int $offset = 0;

  /**
   * Size of the buffer in bytes
   * @var int
   */
  private int $size;

  /**
   * Construct a BufferReader with the given binary data string.
   * @param string $data The binary data to read from
   */
  public function __construct(string $data){
    $this->buffer = $data;
    $this->size = strlen($data);
  }

  /**
   * Get the total size of the buffer in bytes.
   * @return int The size of the buffer
   */
  public function getSize() : int{
    return $this->size;
  }

  /**
   * Get the current offset in the buffer.
   * @return int The current offset
   */
  public function tell() : int{
    return $this->offset;
  }

  /**
   * Move the current offset in the buffer.
   * @param int $offset The offset to move to
   * @param int $whence The reference point for the offset (SEEK_SET, SEEK_CUR, SEEK_END)
   * @throws InvalidArgumentException If an invalid whence value is provided
   * @throws OutOfBoundsException If the new offset is out of bounds
   */
  public function seek(int $offset, int $whence = SEEK_SET) : void{
    $newOffset = match($whence){
      SEEK_SET => $offset,
      SEEK_CUR => $this->offset + $offset,
      SEEK_END => $this->size + $offset,
      default => throw new InvalidArgumentException("Invalid whence value")
    };

    if($newOffset < 0 || $newOffset > $this->size){
      throw new OutOfBoundsException("Offset is out of bounds");
    }

    $this->offset = $newOffset;
  }

  /**
   * Rewind the buffer to the beginning.
   */
  public function rewind() : void{
    $this->seek(0);
  }

  /**
   * Check if the end of the buffer has been reached.
   * @return bool True if the end of the buffer is reached, false otherwise
   */
  public function EOF() : bool{
    return $this->offset >= $this->size;
  }

  /**
   * Reada specified number of bytes from the buffer at the current offset or a given offset.
   * @param int $length The number of bytes to read
   * @param mixed $offset The offset to read from, or null to read from the current offset
   * @throws IOException If the length exceeds available data or if the offset is out of bounds
   * @throws OutOfBoundsException If the offset is out of bounds
   * @return string The bytes read from the buffer
   */
  public function readBytes(int $length, ?int $offset = null) : string{
    $size = $this->size;
    $position = &$this->offset;

    if($length < 0){
      throw new InvalidArgumentException("Length must be non-negative");
    }

    // No offset provided, read from current position
    if($offset === null){
      if($position + $length > $size){
        throw new IOException("Length exceeds available data");
      }

      $data = substr($this->buffer, $position, $length);
      $position += $length;

      return $data;
    }
    else{
      if($offset < 0){
        throw new InvalidArgumentException("Offset must be non-negative");
      }

      if($offset + $length > $size){
        throw new IOException("Length exceeds available data");
      }

      $data = substr($this->buffer, $offset, $length);
      $this->seek($position);

      return $data;
    }
  }
}