<?php
namespace nwniscoding\TLS\Ciphers;

use nwniscoding\TLS\Enums\RecordType;
use nwniscoding\TLS\Enums\Version;

interface Cipher{
  public function encrypt(int $sequence, RecordType $type, Version $version, string $content) : string;

  public function decrypt(int $sequence, RecordType $type, Version $version, string $content) : string;
}