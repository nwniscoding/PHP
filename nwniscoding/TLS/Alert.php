<?php
namespace nwniscoding\TLS;

use nwniscoding\IO\BufferWriter;
use nwniscoding\TLS\Enums\AlertLevel;
use nwniscoding\TLS\Enums\AlertType;

/**
 * Represents a TLS Alert, which is a message sent by either the client or server to indicate an error or warning condition during the TLS handshake or data transmission. An alert consists of a level (warning or fatal) and a description (specific error code). Alerts are used to signal issues such as protocol violations, handshake failures, or other problems that may arise during the TLS communication process.
 */
final readonly class Alert{
  public AlertLevel $level;

  public AlertType $description;

  public function __construct(AlertLevel $level, AlertType $description){
    $this->level = $level;
    $this->description = $description;
  }

  public function __tostring() : string{
    $writer = new BufferWriter();
    $writer->writeUint8($this->level->value);
    $writer->writeUint8($this->description->value);

    return $writer->data();
  }
}