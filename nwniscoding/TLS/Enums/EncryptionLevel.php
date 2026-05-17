<?php
namespace nwniscoding\TLS\Enums;

enum EncryptionLevel{
  case PLAINTEXT;
  case HANDSHAKE;
  case ENCRYPTED;
}