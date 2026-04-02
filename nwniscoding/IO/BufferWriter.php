<?php
namespace nwniscoding\IO;

/**
 * BufferWriter class provides methods for writing data to an in-memory buffer stream.
 */
final class BufferWriter extends Writer{
  public function __construct(int $capacity = 0){
    $stream = fopen('php://memory', 'r+b');

    if(!$stream){
      throw new IOException("Failed to open memory stream");
    }

    parent::__construct($stream);

    if($capacity > 0){
      $this->write(str_repeat("\0", $capacity));
      $this->rewind();
    }
  }
}