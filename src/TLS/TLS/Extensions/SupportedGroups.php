<?php
namespace TLS\Extensions;

use Exception;
use TLS\Enums\ExtensionType;
use TLS\Enums\SupportedGroup as SupportedGroupsEnum;
use TLS\Utils\BufferReader;
use TLS\Utils\BufferWriter;

class SupportedGroups extends Extension{
  private array $groups;

  public function __construct(SupportedGroupsEnum ...$groups){
    parent::__construct(ExtensionType::SUPPORTED_GROUPS);
    $this->groups = $groups;
  }

  public function setGroups(SupportedGroupsEnum ...$groups): void{
    $this->groups = $groups;
  }

  public function getGroups(): array{
    return $this->groups;
  }

  public function encode(): BufferWriter{
    $writer = new BufferWriter;
    $writer->setU16(count($this->groups) * 2);
    
    foreach($this->groups as $group){
      $writer->setU16($group->value);
    }

    return $writer;
  }

  public static function decode(BufferReader $data): static{
    $groups = [];
    $offset = 0;
    $length = $data->getU16();

    while($offset < $length){
      $groups[] = SupportedGroupsEnum::from($data->getU16());
      $offset += 2;
    }
    
    return new self(...$groups);
  }
}