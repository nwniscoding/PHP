<?php
namespace nwniscoding\IO;

use InvalidArgumentException;
use SplFileObject;

/**
 * FileReader is a utility class for reading binary data from a file.
 */
final class FileReader extends Reader{
  /**
   * The file stream for reading data
   * @var SplFileObject
   */
  private SplFileObject $fileStream;

  /**
   * Construct a FileReader for the given file path or File object.
   * @param File|string $file The file to read from, either as a File object or a file path string
   * @throws IOException If the file does not exist or is not a valid file
   */
  public function __construct(File | string $file){
    $file = $file instanceof File ? $file : new File($file);

    if(!$file->exists()){
      throw new IOException("File does not exist");
    }

    if(!$file->isFile()){
      throw new IOException("Path is not a file");
    }

    $this->fileStream = $file->openFile("r");
  }

  /**
   * Get the total size of the file in bytes.
   * @return int The size of the file
   */
  public function getSize() : int{
    return $this->fileStream->getSize();
  }

  /**
   * Get the current offset in the file.
   * @return int The current offset
   */
  public function tell() : int{
    return $this->fileStream->ftell();
  }

  /**
   * Move the current offset in the file.
   * @param int $offset The offset to move to
   * @param int $whence The reference point for the offset (SEEK_SET, SEEK_CUR, SEEK_END)
   * @throws IOException If an error occurs while seeking
   */
  public function seek(int $offset, int $whence = SEEK_SET) : void{
    if($offset < 0 || $this->fileStream->fseek($offset, $whence) === -1){
      throw new IOException("Invalid offset or whence");
    }
  }

  /**
   * Rewind the file to the beginning.
   */
  public function rewind() : void{
    $this->fileStream->rewind();
  }

  /**
   * Read a specified number of bytes from the file, optionally from a specific offset.
   * @param int $length The number of bytes to read
   * @param int|null $offset The offset to read from, or null to read from the current position
   * @return string The binary data read from the file
   * @throws IOException If an error occurs while reading
   */
  protected function readBytes(int $length, ?int $offset = null): string{
    $size = $this->getSize();
    $position = $this->tell();

    if($offset === null){
      if($position + $length > $size){
        throw new IOException("Length exceeds available data");
      }

      return $this->fileStream->fread($length);
    }
    else{
      if($offset < 0){
        throw new InvalidArgumentException("Offset must be non-negative");
      }

      if($offset + $length > $size){
        throw new IOException("Offset and length exceed available data");
      }

      $this->seek($offset);
      $data = $this->fileStream->fread($length);
      $this->seek($position);

      return $data;
    }
  }
}