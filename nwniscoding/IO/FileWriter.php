<?php
namespace nwniscoding\IO;

use function is_string;

final class FileWriter extends Writer{
  public function __construct(File | string $file){
    if(is_string($file)){
      $file = new File($file);
    }

    if(!$file->exists()){
      throw new IOException("File does not exist");
    }

    if(!$file->isFile()){
      throw new IOException("Path is not a file");
    }

    parent::__construct(fopen($file->getPathname(), 'wb'));
  }
}