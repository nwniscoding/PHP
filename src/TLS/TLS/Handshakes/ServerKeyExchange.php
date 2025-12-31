<?php
namespace TLS\Handshakes;

use Exception;
use TLS\Enums\HandshakeType;
use TLS\Enums\SupportedGroups;
use TLS\TLSException;
use TLS\Utils\BufferReader;

class ServerKeyExchange extends Handshake{
  private array $params = [];

  public function __construct(){
    parent::__construct(HandshakeType::SERVER_KEY_EXCHANGE);
  }

  public function encode(): string{
    switch($this->params['type']){
      case 'ECDHE' : 
        return pack(
          'CnCa*n2a*',
          0x3,
          $this->params['named_curve']->value,
          strlen($this->params['public_key']),
          $this->params['public_key'],
          $this->params['signature_algorithm'],
          strlen($this->params['signature']),
          $this->params['signature']
        );
        break;
      case 'DHE' :
        return pack(
          'na*na*na*n2a*',
          strlen($this->params['prime']),
          $this->params['prime'],
          strlen($this->params['generator']),
          $this->params['generator'],
          strlen($this->params['public_key']),
          $this->params['public_key'],
          $this->params['signature_algorithm'],
          strlen($this->params['signature']),
          $this->params['signature']
        );
        break;
      case 'PSK' :
        return pack(
          'na*',
          strlen($this->params['identity']),
          $this->params['identity']
        );
        break;
      default :
        return '';
    }
  }

  public static function decode(string $data): static{
    $buffer = new BufferReader($data);
    $handshake = new self();

    if($handshake->tryECDHE($buffer)){
      return $handshake;
    }

    $buffer->seek(0);

    if($handshake->tryDHE($buffer)){
      return $handshake;
    }

    $buffer->seek(0);

    if($handshake->tryPSK($buffer)){
      return $handshake;
    }

    return $handshake;
  }

  private function tryECDHE(BufferReader &$buffer): bool{
    $start = $buffer->getOffset();

    try{
      if($buffer->getU8() != 0x3){
        $buffer->seek($start);

        return false;
      }

      $id = $buffer->getU16();
      $groups = SupportedGroups::tryFrom($id);

      if($groups === null){
        throw new Exception();
      }

      $key_length = $buffer->getU8();

      if(!in_array($key_length, [32, 65, 97], true)){
        throw new Exception();
      }

      $public_key = $buffer->read($key_length);
      $signature_algorithm = $buffer->getU16();
      $signature = $buffer->read($buffer->getU16());

      if(!$buffer->isEOF()){
        throw new Exception();
      }

      $this->params = [
        'type' => 'ECDHE',
        'curve_type' => 0x3,
        'named_curve' => $groups,
        'public_key' => $public_key,
        'signature_algorithm' => $signature_algorithm,
        'signature' => $signature
      ];

      return true;
    }
    catch(Exception){
      $buffer->seek($start);

      return false;
    }
  }

  private function tryDHE(BufferReader &$buffer): bool{
    $start = $buffer->getOffset();

    try{
      $prime_len = $buffer->getU16();

      if($prime_len < 128 || $prime_len > 1024){
        throw new Exception();
      }

      $prime = $buffer->read($prime_len);

      $gen_len = $buffer->getU16();

      if($gen_len < 1 || $gen_len > 8){
        throw new Exception();
      }

      $generator = $buffer->read($gen_len);

      $y_len = $buffer->getU16();

      if($y_len < 128 || $y_len > 1024){
        throw new Exception();
      }

      $y = $buffer->read($y_len);

      $signature_algorithm = $buffer->getU16();
      $signature = $buffer->read($buffer->getU16());

      if(!$buffer->isEOF()){
        throw new Exception();
      }

      $this->params = [
        'type' => 'DHE',
        'prime' => $prime,
        'generator' => $generator,
        'public_key' => $y,
        'signature_algorithm' => $signature_algorithm,
        'signature' => $signature
      ];

      return true;
    }
    catch(Exception){
      $buffer->seek($start);
      
      return false;
    }
  }

  private function tryPSK(BufferReader &$buffer): bool{
    try{
      $identity_len = $buffer->getU16();
      $identity = $buffer->read($identity_len);

      if(!$buffer->isEOF()){
        throw new Exception();
      }

      $this->params = [
        'type' => 'PSK',
        'identity' => $identity
      ];

      return true;
    }
    catch(Exception){
      return false;
    }
  }

  public function jsonSerialize(): mixed{
    return [
      'handshake_type' => $this->type->name,
      'params' => $this->params,
    ];
  }
}