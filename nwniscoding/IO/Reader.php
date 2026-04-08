<?php
namespace nwniscoding\IO;

use function ord;

/**
 * Reader class provides methods to read various data types from a binary stream.
 */
abstract class Reader{
  /**
   * Reads a specified number of bytes from the stream.
   * @param int $length Number of bytes to read
   * @param ?int $offset Optional offset to read from
   * @return string The read bytes as a string
   */
  abstract protected function readBytes(int $length, ?int $offset = null) : string;

  /**
   * Returns the total size of the stream in bytes.
   * @return int Size of the stream in bytes
   */
  abstract public function getSize() : int;

  /**
   * Returns the current position in the stream.
   * @return int Current position in the stream
   */
  abstract public function tell() : int;

  /**
   * Moves the current position in the stream to a new location.
   * @param int $offset Number of bytes to move the position by
   * @param int $whence Optional parameter that specifies how the offset should be interpreted (SEEK_SET, SEEK_CUR, SEEK_END)
   * @return void
   */
  abstract public function seek(int $offset, int $whence = SEEK_SET) : void;

  /**
   * Resets the current position in the stream to the beginning.
   * @return void
   */
  abstract public function rewind() : void;

  /**
   * Checks if the end of the stream has been reached.
   * @return bool True if the end of the stream is reached, false otherwise
   */
  abstract public function EOF() : bool;

  /**
   * Read a specified number of bytes from the stream and return it as a string.
   * @param int $length Number of bytes to read
   * @param ?int $offset Optional offset to read from (can be int or null)
   * @return string The read bytes as a string
   */
  public function read(int $length, ?int $offset = null) : string{
    return $this->readBytes($length, $offset);
  }

  /**
   * Reads a single byte from the stream and returns it as an unsigned integer.
   * @param ?int $offset Optional offset to read from (can be int or null)
   * @return int The read byte as an unsigned integer
   */
  public function readUint8(?int $offset = null) : int{
    return ord($this->readBytes(1, $offset));
  }

  /**
   * Reads two bytes from the stream and returns it as an unsigned integer.
   * @param ?int $offset Optional offset to read from (can be int or null)
   * @param bool $littleEndian Optional parameter that specifies whether the bytes should be interpreted as little-endian (default is false, meaning big-endian)
   * @return int The read bytes as an unsigned integer
   */
  public function readUint16(?int $offset = null, bool $littleEndian = false) : int{
    $data = $this->readBytes(2, $offset);

    return match($littleEndian){
      true => ord($data[0]) | (ord($data[1]) << 8),
      false => (ord($data[0]) << 8) | ord($data[1])
    };
  }

  /**
   * Reads three bytes from the stream and returns it as an unsigned integer.
   * @param mixed $offset Optional offset to read from (can be int or null)
   * @param bool $littleEndian Optional parameter that specifies whether the bytes should be interpreted as little-endian (default is false, meaning big-endian)
   * @return int The read bytes as an unsigned integer
   */
  public function readUint24(?int $offset = null, bool $littleEndian = false) : int{
    $data = $this->readBytes(3, $offset);

    return match($littleEndian){
      true => ord($data[0]) | (ord($data[1]) << 8) | (ord($data[2]) << 16),
      false => (ord($data[0]) << 16) | (ord($data[1]) << 8) | ord($data[2])
    };
  }

  /**
   * Reads four bytes from the stream and returns it as an unsigned integer.
   * @param mixed $offset Optional offset to read from (can be int or null)
   * @param bool $littleEndian Optional parameter that specifies whether the bytes should be interpreted as little-endian (default is false, meaning big-endian)
   * @return int The read bytes as an unsigned integer
   */
  public function readUint32(?int $offset = null, bool $littleEndian = false) : int{
    $data = $this->readBytes(4, $offset);

    return match($littleEndian){
      true => ord($data[0]) | (ord($data[1]) << 8) | (ord($data[2]) << 16) | (ord($data[3]) << 24),
      false => (ord($data[0]) << 24) | (ord($data[1]) << 16) | (ord($data[2]) << 8) | ord($data[3])
    };
  }

  /**
   * Reads a single byte from the stream and returns it as a signed integer.
   * @param mixed $offset Optional offset to read from (can be int or null)
   * @return int The read byte as a signed integer
   */
  public function readInt8(?int $offset = null) : int{
    $value = $this->readUint8($offset);

    return $value < 0x80 ? $value : $value - 0x100;
  }

  /**
   * Reads two bytes from the stream and returns it as a signed integer.
   * @param mixed $offset Optional offset to read from (can be int or null)
   * @param bool $littleEndian Optional parameter that specifies whether the bytes should be interpreted as little-endian (default is false, meaning big-endian)
   * @return int The read bytes as a signed integer
   */
  public function readInt16(?int $offset = null, bool $littleEndian = false) : int{
    $value = $this->readUint16($offset, $littleEndian);

    return $value < 0x8000 ? $value : $value - 0x10000;
  }

  /**
   * Reads four bytes from the stream and returns it as a signed integer.
   * @param mixed $offset Optional offset to read from (can be int or null)
   * @param bool $littleEndian Optional parameter that specifies whether the bytes should be interpreted as little-endian (default is false, meaning big-endian)
   * @return int The read bytes as a signed integer
   */
  public function readInt32(?int $offset = null, bool $littleEndian = false) : int{
    $value = $this->readUint32($offset, $littleEndian);

    return $value < 0x80000000 ? $value : $value - 0x100000000;
  }

  /**
   * Reads four bytes from the stream and returns it as a floating-point number.
   * @param mixed $offset Optional offset to read from (can be int or null)
   * @param bool $littleEndian Optional parameter that specifies whether the bytes should be interpreted as little-endian (default is false, meaning big-endian)
   * @return float The read bytes as a floating-point number
   */
  public function readFloat(?int $offset = null, bool $littleEndian = false) : float{
    return unpack($littleEndian ? 'g' : 'G', $this->readBytes(4, $offset))[1];
  }

  /**
   * Reads eight bytes from the stream and returns it as a floating-point number.
   * @param mixed $offset Optional offset to read from (can be int or null)
   * @param bool $littleEndian Optional parameter that specifies whether the bytes should be interpreted as little-endian (default is false, meaning big-endian)
   * @return float The read bytes as a floating-point number
   */
  public function readDouble(?int $offset = null, bool $littleEndian = false) : float{
    return unpack($littleEndian ? 'e' : 'E', $this->readBytes(8, $offset))[1];
  }
}