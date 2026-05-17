<?php
namespace nwniscoding\TLS;

use nwniscoding\TLS\Utils\BinaryEncodable;
use function strlen;
use function is_string;

use nwniscoding\IO\BufferWriter;
use nwniscoding\TLS\Handshakes\Handshake;
use nwniscoding\TLS\Enums\RecordType;
use nwniscoding\TLS\Enums\Version;

final readonly class Record implements BinaryEncodable{
  public Version $version;

  public RecordType $type;

  public string | Handshake | Alert $content;

  public function __construct(Version $version, RecordType $type, string | Handshake | Alert $content){
    $this->version = $version;
    $this->type = $type;
    $this->content = $content;
  }

  public static function applicationData(Version $version, string $data) : self{
    return new self($version, RecordType::APPLICATION_DATA, $data);
  }

  public static function handshake(Version $version, Handshake | string $handshake) : self{
    return new self($version, RecordType::HANDSHAKE, $handshake);
  }

  public static function alert(Version $version, Alert $alert) : self{
    return new self($version, RecordType::ALERT, $alert);
  }

  public static function changeCipherSpec(Version $version) : self{
    return new self($version, RecordType::CHANGE_CIPHER, "\1");
  }
  
  public function toBinary() : string{
    $writer = new BufferWriter();
    $content = is_string($this->content) ? $this->content : $this->content->toBinary();
    $writer->writeUint8($this->type->value);
    $writer->writeUint16($this->version->value);
    $writer->writeUint16(strlen($content));
    $writer->write($content);
    
    return $writer->data();
  }
}