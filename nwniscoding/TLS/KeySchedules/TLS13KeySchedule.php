<?php
namespace nwniscoding\TLS\Keyschedules;

use nwniscoding\TLS\Ciphers\CipherInfo;
use nwniscoding\TLS\HandshakeContext;

final class TLS13KeySchedule implements KeySchedule{
    public const string TLS_13_DERIVED_LABEL = "tls13 derived";

  public const string TLS_13_KEY_LABEL = "tls13 key";

  public const string TLS_13_IV_LABEL = "tls13 iv";

  public const string TLS_13_CLIENT_HANDSHAKE_TRAFFIC_LABEL = "tls13 c hs traffic";

  public const string TLS_13_SERVER_HANDSHAKE_TRAFFIC_LABEL = "tls13 s hs traffic";

  private HandshakeContext $context;

  private ?string $earlySecret = null;

  private ?string $derivedSecret = null;

  private ?string $handshakeSecret = null;

  private ?string $serverHandshakeTrafficSecret = null;

  private ?string $clientHandshakeTrafficSecret = null;

  private ?string $serverApplicationTrafficSecret = null;

  private ?string $clientApplicationTrafficSecret = null;

  private ?string $clientKey = null;

  private ?string $clientIV = null;

  private ?string $serverKey = null;

  private ?string $serverIV = null;

  public function __construct(HandshakeContext $context){
    $this->context = $context;
  }

  public function deriveKey(string $sharedSecret) : void{
    $context = $this->context;
    $info = $context->getCipherInfo();

    $clientHello = $context->getClientHello();
    $serverHello = $context->getServerHello();
    $helloHash = hash($info->mac, "{$clientHello->toBinary()}{$serverHello->toBinary()}", true);
    $zeroKey = str_repeat("\0", $info->getMACSize());
    $earlySecret = self::extract($zeroKey, '', $info);
    $emptyHash = hash($info->mac, '', true);
    $derivedSecret = self::expand($earlySecret, self::TLS_13_DERIVED_LABEL, $emptyHash, 48, $info);
    $handshakeSecret = self::extract($sharedSecret, $derivedSecret, $info);
    $serverHandshakeTrafficSecret = self::expand($handshakeSecret, self::TLS_13_SERVER_HANDSHAKE_TRAFFIC_LABEL, $helloHash, 48, $info);
    $clientHandshakeTrafficSecret = self::expand($handshakeSecret, self::TLS_13_CLIENT_HANDSHAKE_TRAFFIC_LABEL, $helloHash, 48, $info);
    $serverKey = self::expand($serverHandshakeTrafficSecret, self::TLS_13_KEY_LABEL, '', 32, $info);
    $serverIV = self::expand($serverHandshakeTrafficSecret, self::TLS_13_IV_LABEL, '', 12, $info);
    $clientKey = self::expand($clientHandshakeTrafficSecret, self::TLS_13_KEY_LABEL, '', 32, $info);
    $clientIV = self::expand($clientHandshakeTrafficSecret, self::TLS_13_IV_LABEL, '', 12, $info);

    $this->earlySecret = $earlySecret;
    $this->derivedSecret = $derivedSecret;
    $this->handshakeSecret = $handshakeSecret;
    $this->serverHandshakeTrafficSecret = $serverHandshakeTrafficSecret;
    $this->clientHandshakeTrafficSecret = $clientHandshakeTrafficSecret;
    $this->serverKey = $serverKey;
    $this->serverIV = $serverIV;
    $this->clientKey = $clientKey;
    $this->clientIV = $clientIV;
  }

  public function getClientKey() : ?string{
    return $this->clientKey;
  }

  public function getClientIV() : ?string{
    return $this->clientIV;
  }

  public function getServerKey() : ?string{
    return $this->serverKey;
  }

  public function getServerIV() : ?string{
    return $this->serverIV;
  }

  public static function extract(string $inputKeyMaterial, string $salt, CipherInfo $info) : string{
    if($salt === ''){
      $salt = str_repeat("\0", $info->getMACSize());
    }

    return hash_hmac($info->mac, $salt, $inputKeyMaterial, true);
  }

  public static function expand(string $secret, string $label, string $context, int $length, CipherInfo $info) : string{
    $ctx = pack('nCa*Ca*', $length, strlen($label), $label, strlen($context), $context);

    $n = ceil($length / $info->getMACSize());
    $outputKeyMaterial = '';
    $t = '';

    for($i = 1; $i <= $n; $i++){
      $c = chr($i);
      $t = hash_hmac($info->mac, "{$t}{$ctx}{$c}", $secret, true);
      $outputKeyMaterial .= $t;
    }

    return substr($outputKeyMaterial, 0, $length);
  }
}