<?php
namespace TLS\Extensions;

use TLS\Enums\ExtensionType;
use TLS\Enums\SupportedGroup as SupportedGroupsEnum;
use TLS\TLSException;
use TLS\Utils\BufferReader;

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

  public function encode(): string{
    return pack('n*', \count($this->groups) * 2, ...array_map(fn($g) => $g->value, $this->groups));
  }

  public static function decode(string $data): static{
    $buffer = new BufferReader($data);
    $groups = [];
    $offset = 0;
    $length = $buffer->getU16();

    while($offset < $length){
      $groups[] = SupportedGroupsEnum::tryFrom($buffer->getU16());
      $offset += 2;
    }

    if($offset + $length !== $buffer->getSize())
      throw new TLSException('SupportedGroups extension length mismatch');

    return new self(...$groups);
  }

  public function jsonSerialize(): mixed{
    return [
      'type' => $this->getType()->name,
      'groups' => array_map(fn($g) => $g->name, $this->groups),
    ];
  }
}