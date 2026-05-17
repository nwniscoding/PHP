<?php
namespace nwniscoding\TLS\Engines;

use nwniscoding\TLS\Enums\ExtensionType;
use nwniscoding\TLS\Enums\RecordType;
use nwniscoding\TLS\Enums\Version;
use nwniscoding\TLS\Exceptions\TLSException;
use nwniscoding\TLS\Extensions\KeyShare;
use nwniscoding\TLS\Handshakes\ClientHello;
use nwniscoding\TLS\Handshakes\Handshake;
use nwniscoding\TLS\Handshakes\ServerHello;
use nwniscoding\TLS\Keyschedules\TLS13KeySchedule;
use nwniscoding\TLS\KeyShareEntry;
use nwniscoding\TLS\Record;
use nwniscoding\TLS\Sessions\ClientSession;
use nwniscoding\TLS\Sessions\Session;
use RuntimeException;

final class TLS13Engine extends TLSEngine{
  public function __construct(Session $session){
    parent::__construct($session, new TLS13KeySchedule($session->handshakeContext));
    $this->on(Handshake::class, [$this, 'onHandshake']);
    $this->on(ServerHello::class, [$this, 'onServerHello']);
    $this->on(Record::class, [$this, 'onRecord']);
  }
  
  public function startAsClient(ClientHello $handshake) : void{
    $session = $this->session;
    $context = $session->handshakeContext;

    if(!($session instanceof ClientSession)){
      throw new RuntimeException("ClientSession is required to start a TLS 1.3 client handshake");
    }

    $context->addHandshake($handshake);
    $session->send(Record::handshake(Version::TLS_13, $handshake));

    foreach($session->receive() as $record){
      $this->handleRecord($record);
    }
  }

  public function startAsServer(ServerHello $handshake) : void{

  }

  protected function onServerHello(ServerHello $serverHello) : void{
    $session = $this->session;
    $context = $session->handshakeContext;
    $clientHello = $context->getClientHello();
    $serverKeyShare = $serverHello->extensions[ExtensionType::KEY_SHARE->value] ?? null;
    $clientKeyShare = $clientHello->extensions[ExtensionType::KEY_SHARE->value] ?? null;
    $keySchedule = $this->keySchedule;

    if(!($serverKeyShare instanceof KeyShare) || !($clientKeyShare instanceof KeyShare)){
      throw new TLSException("Both client and server must provide a key share extension for TLS 1.3");
    }

    if(!($keySchedule instanceof TLS13KeySchedule)){
      throw new RuntimeException("TLS13KeySchedule is required for TLS 1.3 handshakes");
    }

    $serverKeyEntry = $serverKeyShare->getCurrentKeyShare();
    $clientKeyEntry = $clientKeyShare->getKeyShareByGroup($serverKeyEntry->group);
    $sharedSecret = openssl_pkey_derive($serverKeyEntry->group->wrapPublicKey($serverKeyEntry->publicKey), $clientKeyEntry->privateKey);

    $keySchedule->deriveKey($sharedSecret);
  }

  protected function onHandshake(Handshake $handshake) : void{
    if($handshake instanceof Encrypted){
      return;
    }

    $this->session->handshakeContext->addHandshake($handshake);
  }

  protected function onRecord(Record $record) : void{
    if($record->type === RecordType::HANDSHAKE || $record->type === RecordType::CHANGE_CIPHER) return;

    if(!$this->keySchedule instanceof TLS13KeySchedule){
      throw new TLSException("TLS 1.3 key schedule is required to decrypt application data");
    }


    $info = $this->session->handshakeContext->getCipherInfo();
    $content = $record->content;
    $authTag = substr($content, -16);
    $ciphertext = substr($content, 0, -16);

    $seq = $this->session->nextServerSequence();

    $iv = $this->keySchedule->getServerIV();
    $nonce = $iv ^ pack('J', $seq);
    $aad = pack("Cnn", $record->type->value, 0x0303, strlen($content));

    $data = openssl_decrypt(
      $ciphertext, 
      $info->encryption, 
      $this->keySchedule->getServerKey(), 
      OPENSSL_RAW_DATA, 
      $nonce,
      $authTag, 
      $aad
    );

    var_dump($data);
  }
}