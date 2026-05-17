<?php
namespace nwniscoding\TLS\Sessions;

use nwniscoding\IO\BufferReader;
use nwniscoding\TLS\Ciphers\Cipher;
use nwniscoding\TLS\Engines\TLS12Engine;
use nwniscoding\TLS\Engines\TLS13Engine;
use nwniscoding\TLS\Engines\TLSEngine;
use nwniscoding\TLS\Enums\EncryptionLevel;
use nwniscoding\TLS\Enums\HandshakeType;
use nwniscoding\TLS\Enums\RecordType;
use nwniscoding\TLS\Enums\Version;
use nwniscoding\TLS\Exceptions\TLSException;
use nwniscoding\TLS\HandshakeContext;
use nwniscoding\TLS\Handshakes\Handshake;
use nwniscoding\TLS\Record;
use nwniscoding\TLS\RecordParser;
use nwniscoding\TLS\TLSContext;
use Socket;

abstract class Session{
  protected EncryptionLevel $clientLevel = EncryptionLevel::PLAINTEXT;

  protected EncryptionLevel $serverLevel = EncryptionLevel::PLAINTEXT;

  protected Socket $socket;
  
  public readonly TLSContext $context;

  public readonly HandshakeContext $handshakeContext;

  protected TLSEngine $engine;

  protected ?Cipher $clientCipher = null;

  protected ?Cipher $serverCipher = null;

  protected int $clientSequence = 0;

  protected int $serverSequence = 0;

  public function __construct(Socket $socket, TLSContext $context){
    $this->socket = $socket;
    $this->context = $context;
    $this->handshakeContext = new HandshakeContext();

    $this->engine = match($context->version){
      Version::TLS_12 => new TLS12Engine($this),
      Version::TLS_13 => new TLS13Engine($this),
    };
  }

  public function setClientCipher(Cipher $cipher) : void{
    $this->clientCipher = $cipher;
  }

  public function setServerCipher(Cipher $cipher) : void{
    $this->serverCipher = $cipher;
  }

  public function getClientCipher() : ?Cipher{
    return $this->clientCipher;
  }

  public function getServerCipher() : ?Cipher{
    return $this->serverCipher;
  }

  public function getHandshakeContext() : HandshakeContext{
    return $this->handshakeContext;
  }

  public function getClientLevel() : EncryptionLevel{
    return $this->clientLevel;
  }

  public function getServerLevel() : EncryptionLevel{
    return $this->serverLevel;
  }

  public function setClientLevel(EncryptionLevel $level) : void{
    $this->clientLevel = $level;
  }

  public function setServerLevel(EncryptionLevel $level) : void{
    $this->serverLevel = $level;
  }

  public function send(Record ...$records) : void{
    
    socket_write($this->socket, join('', array_map(fn($record) => $record->toBinary(), $records)));
  }

  public function receive(int $length = 4096) : iterable{
    $data = socket_read($this->socket, $length);

    foreach(RecordParser::parse(new BufferReader($data), $this) as $record){
      yield $record;
    }
  }

  public function nextClientSequence(): int { return $this->clientSequence++; }
  public function nextServerSequence(): int { return $this->serverSequence++; }

  abstract public function negotiate() : void;

  abstract public function sendData(string $data) : void;
}