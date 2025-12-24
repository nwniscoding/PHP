<?php
namespace nwniscoding\TLS\Utils;

use OutOfRangeException;
use Stringable;

class Buffer implements Stringable{
  private string $data;

  private int $end;

  private int $start;

  private int $cursor = 0;

  public function __construct(string $data = '', int $start = 0, ?int $end = null){
    if($start < 0 || $end !== null && $end < $start || $end !== null && $end > \strlen($data))
      throw new OutOfRangeException("Invalid start or end position for buffer");

    $this->data = $data;
    $this->start = $start;
    $this->cursor = $start;
    $this->end = $end ?? \strlen($data);
  }

  public function isEOF(): bool{
    return $this->cursor >= $this->end;
  }

  public function resetCursor(): void{
    $this->cursor = $this->start;
  }
  
  public function getCursor(): int{
    return $this->cursor - $this->start;
  }

  public function setCursor(int $position): void{
    $this->cursor = $position + $this->start;
  }

  public function move(int $position): void{
    $this->cursor += $position;
  }

  public function getData(): string{
    return $this->data;
  }

  public function getU8(): int{
    if($this->isEOF()) throw new OutOfRangeException("Cursor is at the end of the buffer");

    return \ord($this->data[$this->cursor++]);
  }

  public function setU8(int $value): void{
    $this->data[$this->cursor++] = \chr($value & 0xFF);
    $this->end = max($this->end, $this->cursor);
  }

  public function getU16(): int{
    return ($this->getU8() << 8) | $this->getU8();
  }

  public function setU16(int $value): void{
    $this->setU8(($value >> 8) & 0xFF);
    $this->setU8($value & 0xFF);
  }

  public function getU32(): int{
    return ($this->getU8() << 24) | ($this->getU8() << 16) | ($this->getU8() << 8) | $this->getU8();
  }

  public function setU32(int $value): void{
    $this->setU8(($value >> 24) & 0xFF);
    $this->setU8(($value >> 16) & 0xFF);
    $this->setU8(($value >> 8) & 0xFF);
    $this->setU8($value & 0xFF);
  }

  public function write(string $data): void{
    $length = \strlen($data);

    for($i = 0; $i < $length; $i++){
      $this->data[$this->cursor++] = $data[$i];
    }

    $this->end = max($this->end, $this->cursor);
  }

  public function read(int $length): Buffer{
    if($this->cursor + $length > $this->end)
      throw new OutOfRangeException("Not enough data to read {$length} bytes from buffer");

    $this->cursor += $length;

    return new Buffer($this->data, $this->cursor - $length, $this->cursor);
  }

  public function __tostring(): string{
    return substr($this->data, $this->start, $this->end - $this->start);
  }
}