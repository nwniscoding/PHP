<?php
namespace nwniscoding\TLS;

use nwniscoding\IO\BufferReader;
use nwniscoding\TLS\Enums\AlertLevel;
use nwniscoding\TLS\Enums\AlertType;
use nwniscoding\TLS\Enums\EncryptionLevel;
use nwniscoding\TLS\Enums\RecordType;
use nwniscoding\TLS\Enums\Version;
use nwniscoding\TLS\Handshakes\Encrypted;
use nwniscoding\TLS\Handshakes\HandshakeParser;
use nwniscoding\TLS\Sessions\ClientSession;
use nwniscoding\TLS\Sessions\Session;

final class RecordParser{
  public static function parse(BufferReader $reader, Session $session) : iterable{
    while(!$reader->EOF()){
      if($session instanceof ClientSession){
        $hasCipher = $session->getServerLevel();
      }
      else{
        $hasCipher = $session->getClientLevel();
      }
      
      $type = RecordType::from($reader->readUint8());
      $version = Version::from($reader->readUint16());
      $length = $reader->readUint16();
      $data = $reader->extract($length);

      switch($type){
        case RecordType::HANDSHAKE : 
          $result = $hasCipher === EncryptionLevel::ENCRYPTED ? new Encrypted($data->readData()) : HandshakeParser::parse($data, $session->handshakeContext);
          break;
        case RecordType::ALERT :
          $result = new Alert(AlertLevel::from($data->readUint8()), AlertType::from($data->readUint8()));
          break;
        case RecordType::APPLICATION_DATA:
        case RecordType::CHANGE_CIPHER:
          $result = $data->readData();
          break;
      }

      yield new Record($version, $type, $result);
    }
  }
}