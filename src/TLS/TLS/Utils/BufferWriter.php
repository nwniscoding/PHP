<?php
namespace TLS\Utils;

use OverflowException;
use Stringable;

class BufferWriter implements Stringable{
  private string $data;

  private int $offset = 0;

  private readonly int $size;

  public function __construct(int $size){
    $this->data = str_repeat("\0", $size);
    $this->size = $size;
  }

  public function setU8(int $value): void{
    $this->hasBufferOverflowed(1);
    $this->data[$this->offset++] = \chr($value & 0xFF);
  }

  public function setU16(int $value): void{
    $this->hasBufferOverflowed(2);
    $this->data[$this->offset++] = \chr(($value >> 8) & 0xFF);
    $this->data[$this->offset++] = \chr($value & 0xFF);
  }

  public function setU32(int $value): void{
    $this->hasBufferOverflowed(4);
    $this->data[$this->offset++] = \chr(($value >> 24) & 0xFF);
    $this->data[$this->offset++] = \chr(($value >> 16) & 0xFF);
    $this->data[$this->offset++] = \chr(($value >> 8) & 0xFF);
    $this->data[$this->offset++] = \chr($value & 0xFF);
  }

  public function setU64(int $value): void{
    $this->setU32(($value >> 32) & 0xFFFFFFFF);
    $this->setU32($value & 0xFFFFFFFF);
  }

  public function write(string $data): void{
    $len = \strlen($data);

    $this->hasBufferOverflowed($len);

    for($i = 0; $i < $len; $i++){
      $this->data[$this->offset++] = $data[$i];
    }
  }
  
  public function __tostring(): string{
    return $this->data;
  }

  private function hasBufferOverflowed(int $length): void{
    if($this->offset + $length > $this->size){
      throw new OverflowException("Buffer overflow: Attempted to write " . ($this->offset + $length - $this->size) . " bytes beyond buffer size of {$this->size} bytes.");
    }
  }
}