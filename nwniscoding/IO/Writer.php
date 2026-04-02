<?php
namespace nwniscoding\IO;

use function chr;
use function is_resource;
use InvalidArgumentException;

/**
 * Writer class provides methods for writing various data types to a stream resource.
 */
abstract class Writer{
  /**
   * The stream resource to which data will be written.
   * @var mixed
   */
  private mixed $stream;

  /**
   * Initializes the Writer with a stream resource.
   * @param mixed $stream The stream resource to write to.
   * @throws InvalidArgumentException If the provided stream is not a valid resource.
   */
  public function __construct(mixed $stream){
    if(!is_resource($stream)){
      throw new InvalidArgumentException("Stream must be a resource");
    }

    $this->stream = $stream;
  }

  /**
   * Gets the current position of the stream pointer.
   * @return int The current position of the stream pointer.
   * @throws IOException If there was an error getting the current position.
   */
  public function tell() : int{
    $position = ftell($this->stream);

    if($position === false){
      throw new IOException("Failed to get current position");
    }

    return $position;
  }

  /**
   * Seeks to a specific position in the stream.
   * @param int $offset The offset to seek to.
   * @param int $whence The reference point for the offset (SEEK_SET, SEEK_CUR, SEEK_END).
   * @throws IOException If there was an error seeking to the specified position.
   */
  public function seek(int $offset, int $whence = SEEK_SET) : void{
    if($offset < 0 || fseek($this->stream, $offset, $whence) === -1){
      throw new IOException("Invalid offset or whence");
    }
  }

  /**
   * Rewinds the stream pointer to the beginning of the stream.
   * @throws IOException If there was an error rewinding the stream.
   */
  public function rewind() : void{
    if(rewind($this->stream) === false){
      throw new IOException("Failed to rewind stream");
    }
  }

  /**
   * Writes a string to the stream at the current position or at a specified offset.
   * @param string $data The string data to write.
   * @param int|null $offset The optional offset to write at. If null, writes at the current position.
   * @throws IOException If there was an error writing to the stream.
   */
  public function write(string $data, ?int $offset = null) : void{
    $this->writeBytes($data, $offset);
  }

  /**
   * Writes an unsigned 8-bit integer to the stream.
   * @param int $value The value to write.
   * @param int|null $offset The optional offset to write at. If null, writes at the current position.
   * @throws IOException If there was an error writing to the stream.
   */
  public function writeUint8(int $value, ?int $offset = null) : void{
    $this->writeBytes(chr($value & 0xFF), $offset);
  }

  /**
   * Writes an unsigned 16-bit integer to the stream in either little-endian or big-endian format.
   * @param int $value The value to write.
   * @param int|null $offset The optional offset to write at. If null, writes at the current position.
   * @param bool $littleEndian Whether to write the value in little-endian format (true) or big-endian format (false).
   * @throws IOException If there was an error writing to the stream.
   */
  public function writeUint16(int $value, ?int $offset = null, bool $littleEndian = false) : void{
    $bytes = $littleEndian
      ? chr($value & 0xFF) . chr(($value >> 8) & 0xFF)
      : chr(($value >> 8) & 0xFF) . chr($value & 0xFF);

    $this->writeBytes($bytes, $offset);
  }

  public function writeUint24(int $value, ?int $offset = null, bool $littleEndian = false) : void{
    $bytes = $littleEndian
      ? chr($value & 0xFF) . chr(($value >> 8) & 0xFF) . chr(($value >> 16) & 0xFF)
      : chr(($value >> 16) & 0xFF) . chr(($value >> 8) & 0xFF) . chr($value & 0xFF);

    $this->writeBytes($bytes, $offset);
  }

  /**
   * Writes an unsigned 32-bit integer to the stream in either little-endian or big-endian format.
   * @param int $value The value to write.
   * @param int|null $offset The optional offset to write at. If null, writes at the current position.
   * @param bool $littleEndian Whether to write the value in little-endian format (true) or big-endian format (false).
   * @throws IOException If there was an error writing to the stream.
   */
  public function writeUint32(int $value, ?int $offset = null, bool $littleEndian = false) : void{
    $bytes = $littleEndian
      ? chr($value & 0xFF) . chr(($value >> 8) & 0xFF) . chr(($value >> 16) & 0xFF) . chr(($value >> 24) & 0xFF)
      : chr(($value >> 24) & 0xFF) . chr(($value >> 16) & 0xFF) . chr(($value >> 8) & 0xFF) . chr($value & 0xFF);

    $this->writeBytes($bytes, $offset);
  }

  /**
   * Writes a 32-bit floating-point number to the stream in either little-endian or big-endian format.
   * @param float $value The value to write.
   * @param int|null $offset The optional offset to write at. If null, writes at the current position.
   * @param bool $littleEndian Whether to write the value in little-endian format (true) or big-endian format (false).
   * @throws IOException If there was an error writing to the stream.
   */
  public function writeFloat(float $value, ?int $offset = null, bool $littleEndian = false) : void{
    $bytes = pack($littleEndian ? 'g' : 'G', $value);
    $this->writeBytes($bytes, $offset);
  }

  /**
   * Writes a 64-bit floating-point number to the stream in either little-endian or big-endian format.
   * @param float $value The value to write.
   * @param int|null $offset The optional offset to write at. If null, writes at the current position.
   * @param bool $littleEndian Whether to write the value in little-endian format (true) or big-endian format (false).
   * @throws IOException If there was an error writing to the stream.
   */
  public function writeDouble(float $value, ?int $offset = null, bool $littleEndian = false) : void{
    $bytes = pack($littleEndian ? 'e' : 'E', $value);
    $this->writeBytes($bytes, $offset);
  }

  /**
   * Closes the stream resource.
   * @throws IOException If there was an error closing the stream.
   */
  public function close() : void{
    if(@fclose($this->stream) === false){
      throw new IOException("Failed to close stream");
    }
  }

  /**
   * Gets the entire contents of the stream as a string.
   * @return string The contents of the stream.
   * @throws IOException If there was an error reading from the stream.
   */
  public function data() : string{
    return stream_get_contents($this->stream, -1, 0);
  }

  /**
   * Write a string to the stream at the current position or at a specified offset.
   * @param string $data The string data to write.
   * @param mixed $offset The optional offset to write at. If null, writes at the current position.
   * @return void
   */
  private function writeBytes(string $data, ?int $offset = null) : void{
    if($offset === null){
      $this->fwrite($data);
      return;
    }
    else{
      $position = $this->tell();
  
      $this->seek($offset);
      $this->fwrite($data);
      $this->seek($position);
    }
  }

  /**
   * Writes raw bytes to the stream.
   * @param string $data The raw byte data to write.
   * @throws IOException If there was an error writing to the stream.
   */
  private function fwrite(string $data) : void{
    if(fwrite($this->stream, $data) === false){
      throw new IOException("Failed to write data");
    }
  }

  /**
   * Destructor to ensure the stream is closed when the Writer object is destroyed.
   */
  public function __destruct(){
    $this->close();
  }
}