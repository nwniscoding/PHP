<?php
namespace TLS\Utils;

use UnderflowException;

class BufferReader{
  private readonly string $data;

  private int $offset = 0;

  private readonly int $size;

  public function __construct(string $data){
    $this->data = $data;
    $this->size = \strlen($data);
  }

  public function getOffset(): int{
    return $this->offset;
  }

  public function getSize(): int{
    return $this->size;
  }

  public function isEOF(): bool{
    return $this->offset >= $this->size;
  }

  public function getU8(): int{
    $this->hasBufferUnderflowed(1);
    return \ord($this->data[$this->offset++]);
  }

  public function getU16(): int{
    $this->hasBufferUnderflowed(2);
    return \ord($this->data[$this->offset++]) << 8 | \ord($this->data[$this->offset++]);
  }

  public function getU32(): int{
    $this->hasBufferUnderflowed(4);
    return (\ord($this->data[$this->offset++]) << 24) |
           (\ord($this->data[$this->offset++]) << 16) |
           (\ord($this->data[$this->offset++]) << 8)  |
           \ord($this->data[$this->offset++]);
  }

  public function getU64(): int{
    $high = $this->getU32();
    $low = $this->getU32();

    return ($high << 32) | $low;
  }

  public function read(int $length): string{
    $this->hasBufferUnderflowed($length);

    $data = \substr($this->data, $this->offset, $length);
    $this->offset += $length;

    return $data;
  }

  private function hasBufferUnderflowed(int $length): void{
    if($this->offset + $length > $this->size){
      throw new UnderflowException("Buffer underflow: Attempted to read " . ($this->offset + $length - $this->size) . " bytes beyond buffer size of " . $this->size . " bytes.");
    }
  }
}