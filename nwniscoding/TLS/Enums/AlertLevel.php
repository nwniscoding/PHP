<?php
namespace nwniscoding\TLS\Enums;

/**
 * Enumeration of TLS Alert Levels as per IANA registry.
 */
enum AlertLevel : int{
  case WARNING = 1;
  case FATAL = 2;
}