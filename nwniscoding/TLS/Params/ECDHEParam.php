<?php
namespace nwniscoding\TLS\Params;

use function strlen;
use nwniscoding\IO\BufferReader;
use nwniscoding\IO\BufferWriter;
use nwniscoding\TLS\Enums\SupportedGroup;

final readonly class ECDHEParam implements Param{
  public string $publicKey;

  public SupportedGroup $curveId;

  public ?int $curveType = null;
  
  public function __construct(string $publicKey, SupportedGroup $curveId, ?int $curveType = null){
    $this->publicKey = $publicKey;
    $this->curveId = $curveId;
    $this->curveType = $curveType;
  }

  public static function decode(BufferReader $reader, int $type = Param::SERVER) : static{
    if($type === Param::CLIENT){
      $publicKey = $reader->read($reader->readUint8());
    }
    else{
      $curveType = $reader->readUint8();
      $curveId = SupportedGroup::tryFrom($reader->readUint16());
      $publicKey = $reader->read($reader->readUint8());
    }
    
    return new static($publicKey, $curveId, $curveType ?? null);
  }

  public function __tostring() : string{
    $writer = new BufferWriter();

    if($this->curveType !== null){
      $writer->writeUint8($this->curveType);
    }

    if($this->curveId !== null){
      $writer->writeUint16($this->curveId->value);
    }

    
    $writer->writeUint8(strlen($this->publicKey));
    $writer->write($this->publicKey);
    
    return $writer->data();
  }
}