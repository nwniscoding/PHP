<?php
namespace nwniscoding\TLS\Engines;

use nwniscoding\IO\BufferReader;
use nwniscoding\TLS\Enums\EncryptionLevel;
use nwniscoding\TLS\Exceptions\SessionException;
use nwniscoding\TLS\Exceptions\TLSException;
use nwniscoding\TLS\Handshakes\ClientKeyExchange;
use nwniscoding\TLS\Handshakes\Encrypted;
use nwniscoding\TLS\Handshakes\Finished;
use nwniscoding\TLS\Handshakes\HandshakeParser;
use nwniscoding\TLS\Handshakes\ServerHelloDone;
use nwniscoding\TLS\Handshakes\ServerKeyExchange;
use nwniscoding\TLS\KeyExchanges\KeyExchangeFactory;
use nwniscoding\TLS\KeySchedules\TLS12KeySchedule;
use nwniscoding\TLS\Sessions\ClientSession;
use nwniscoding\TLS\Utils\EventEmitter;
use RuntimeException;
use Socket;
use function is_string;

use nwniscoding\TLS\Enums\RecordType;
use nwniscoding\TLS\Enums\Version;
use nwniscoding\TLS\Handshakes\ClientHello;
use nwniscoding\TLS\Handshakes\Handshake;
use nwniscoding\TLS\Handshakes\ServerHello;
use nwniscoding\TLS\Record;
use nwniscoding\TLS\Sessions\Session;

final class TLS12Engine extends TLSEngine{
  use EventEmitter;

  public function __construct(Session $session){
    parent::__construct($session, new TLS12KeySchedule($session->handshakeContext));
    $this->on(ServerHelloDone::class, [$this, 'onServerHelloDone']);
    $this->on(Handshake::class, [$this, 'onHandshake']);
    $this->on(Encrypted::class, [$this, 'onEncrypted']);
    $this->on(Record::class, [$this, 'onRecord']);
  }

  public function startAsClient(ClientHello $handshake) : void{
    $session = $this->session;
    $context = $session->handshakeContext;

    $context->addHandshake($handshake);
    $session->send(Record::handshake(Version::TLS_12, $handshake));

    foreach($session->receive() as $record){
      $this->handleRecord($record);
    }
  }

  public function startAsServer(ServerHello $handshake) : void{
  }

  protected function onEncrypted(Encrypted $handshake) : void{
    $session = $this->session;
    $keySchedule = $this->keySchedule;

    if(!($keySchedule instanceof TLS12KeySchedule)){
      throw new TLSException("Expected TLS 1.2 key schedule");
    }

    if($session instanceof ClientSession){
      $decrypted = $session->getServerCipher()->decrypt(
        $session->nextServerSequence(), 
        RecordType::HANDSHAKE, 
        Version::TLS_12, 
        $handshake->content
      );

      $handshake = HandshakeParser::parse(new BufferReader($decrypted), $session->handshakeContext);

      if(!($handshake instanceof Finished)){
        throw new TLSException("Expected finished handshake");
      }

      $verifyData = $handshake->verifyData;
      $expectedVerifyData = $keySchedule->verifyData(TLS12KeySchedule::TLS_12_SERVER_FINISHED_LABEL);
      
      $session->handshakeContext->addHandshake($handshake);

      if(!hash_equals($verifyData, $expectedVerifyData)){
        throw new TLSException("Server finished verify data does not match expected value");
      }
    }
    else{
      // This is for server session, which is not implemented yet.
    }
  }

  protected function onRecord(Record $record) : void{
    if($record->type === RecordType::CHANGE_CIPHER){
      if($this->session instanceof ClientSession){
        $this->session->setServerLevel(EncryptionLevel::ENCRYPTED);
      }
      else{
        $this->session->setClientLevel(EncryptionLevel::ENCRYPTED);
      }
    }
  }

  protected function onServerHelloDone() : void{
    $session = $this->session;
    $keySchedule = $this->keySchedule;
    $context = $session->handshakeContext;
    $info = $context->getCipherInfo();
    $keyExchange = KeyExchangeFactory::create($session);

    // This allows editor to understand that $session is a ClientSession, which is necessary to access the getIdentity() method.
    if(!($session instanceof ClientSession)){
      throw new SessionException("Expected client session");
    }

    // This allows editor to understand that $keySchedule is a TLS12KeySchedule, which is necessary to access the verifyData() method.
    if(!($keySchedule instanceof TLS12KeySchedule)){
      throw new TLSException("Expected TLS 1.2 key schedule");
    }

    $clientKeyExchange = new ClientKeyExchange(
      $keyExchange->getParam(), 
      $info->authentication === 'psk' ?  $session->getIdentity() : null
    );

    $context->addHandshake($clientKeyExchange);

    $keySchedule->deriveKey($keyExchange->getSharedSecret());
    $session->setClientCipher($keySchedule->getClientKey());
    $session->setServerCipher($keySchedule->getServerKey());

    $verifyData = $keySchedule->verifyData(TLS12KeySchedule::TLS_12_CLIENT_FINISHED_LABEL);
    $finished = new Finished($verifyData);

    $context->addHandshake($finished);

    $session->send(
      Record::handshake(Version::TLS_12, $clientKeyExchange), 
      Record::changeCipherSpec(Version::TLS_12), 
      Record::handshake(
        Version::TLS_12, 
        $session->getClientCipher()->encrypt(
          $session->nextClientSequence(), 
          RecordType::HANDSHAKE, 
          Version::TLS_12, 
          $finished->toBinary()
        )
      )
    );

    $session->setClientLevel(EncryptionLevel::ENCRYPTED);

    foreach($session->receive() as $record){
      $this->handleRecord($record);
    }
  }

  protected function onHandshake(Handshake $handshake) : void{
    if($handshake instanceof Encrypted){
      return;
    }

    $this->session->handshakeContext->addHandshake($handshake);
  }

  protected function onServerKeyExchange(ServerKeyExchange $serverKeyExchange) : void{
    $context = $this->session->handshakeContext;
    $certficate = $context->getCertificate();
    $info = $context->getCipherInfo();
    $signatureParam = $serverKeyExchange?->signatureParam;
    $keyExchangeParam = $serverKeyExchange?->keyExchangeParam;
    
    if($signatureParam === null) return;

    if($info->authentication === 'rsa' || $info->authentication === 'ecdsa'){
      $serverHello = $context->getServerHello();
      $clientHello = $context->getClientHello();

      $signedData = "{$clientHello->random}{$serverHello->random}{$keyExchangeParam}";

      if(!openssl_verify($signedData, $signatureParam->signature, $certficate->certificates[0], 'sha256')){
        throw new TLSException("Server key exchange signature verification failed");
      }
    }
  }
}
