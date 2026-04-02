<?php
namespace nwniscoding\IO;

use function strlen;

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * Represents a file or directory which extends the SPLFileInfo class and provides additional methods for file and directory manipulation.
 */
final class File extends SPLFileInfo{
  /**
   * Constants representing file.
   */
  public const int FILE = 1 << 0;
  
  /**
   * Constants representing folder.
   */
  public const int FOLDER = 1 << 1;

  /**
   * Constants representing all types.
   */
  public const int ALL = self::FILE | self::FOLDER;

  /**
   * Helper constant for the directory separator.
   */
  private const DS = DIRECTORY_SEPARATOR;

  /**
   * Checks if the file or directory exists at the specified path.
   * @return bool
   */
  public function exists() : bool{
    return file_exists($this->getPathname());
  }

  /**
   * Creates a file for the specified path.
   * @return bool true if the file was created successfully, false if the file already exists or if an error occurred
   */
  public function createFile() : bool{
    @mkdir($this->getPath(), 0777, true);

    return !$this->exists() && touch($this->getPathname());
  }

  /**
   * Creates a folder for the specified path.
   * @return bool true if the folder was created successfully, false if the folder already exists or if an error occurred
   */
  public function createFolder() : bool{
    return !$this->exists() && @mkdir($this->getPathname(), 0777, true);
  }

  /**
   * Deletes the file or directory at the specified path.
   * @return bool true if the file or directory was deleted successfully, false otherwise
   */
  public function delete() : bool{
    if(!$this->exists()) return false;

    if($this->isFile() || $this->isLink()){
      return unlink($this->getPathname());
    }

    $result = $this->getAll();

    uksort($result, [$this, 'longestPath']);

    foreach($result as $file){
      if($file->isDir() && !rmdir($file->getPathname())) return false;

      if($file->isFile() && !unlink($file->getPathname())) return false;
    }

    return rmdir($this->getPathname());
  }

  /**
   * Set the file permissions for the file or directory at the specified path.
   * @param int $perms The permissions to set, represented as an octal number (e.g., 0755).
   * @return bool true if the permissions were set successfully, false otherwise
   */
  public function setPerms(int $perms) : bool{
    return @chmod($this->getPathname(), $perms & 0777);
  }

  /**
   * Renames the file or directory at the specified path to the given name.
   * @param string $name The new name for the file or directory.
   * @return bool true if the file or directory was renamed successfully, false otherwise
   */
  public function rename(string $name) : bool{
    return @rename($this->getPathname(), $this->getPath() . self::DS . $name);
  }

  /**
   * Copies the file or directory at the specified path to a new location.
   * @param string $newPath The destination path where the file or directory should be copied to.
   * @return bool true if the file or directory was copied successfully, false otherwise
   */
  public function copy(string $newPath) : bool{
    if($this->isDir()){
      $result = $this->getAll();
      uksort($result, [$this, 'shortestPath']);


      foreach($result as $path => $info){
        $newFilePath = substr_replace($path, $newPath, 0, strpos($path, self::DS));
        
        if($info->isDir()){
          // This might fail but we can ignore that.
          @mkdir($newFilePath, 0777, true);
        }
        else{
          copy($path, $newFilePath);
        }
      }

      return true;
    }

    return copy($this->getPathname(), $newPath . self::DS . $this->getBasename());
  }

  /**
   * Gets all the files and directories.
   * @param int $type the type of files to get (0 for files, 1 for folders, 2 for all)
   * @return self[] an array of File objects representing the files and directories, or an empty array if the path is not a directory
   */
  public function getAll(int $type = self::ALL) : array{
    if(!$this->isDir()) return [];

    $files = [];

    $iterator = new RecursiveIteratorIterator(
      new RecursiveDirectoryIterator(
        $this->getPathname(), 
        RecursiveDirectoryIterator::SKIP_DOTS
      ), 
      RecursiveIteratorIterator::SELF_FIRST
    );

    $iterator->setInfoClass(self::class);

    foreach($iterator as $file){
      if($type === self::FILE && !$file->isFile()) continue;
      if($type === self::FOLDER && !$file->isDir()) continue;

      $files[$file->getPathname()] = $file;
    }

    return $files;
  }

  /**
   * Get the size of the file or directory.
   * @return int The size of the file or directory.
   */
  public function getSize() : int{
    if(!$this->exists()) return 0;

    if($this->isFile()) return filesize($this->getPathname());

    $files = $this->getAll(self::FILE);
    $size = 0;

    foreach($files as $file){
      $size += $file->getSize();
    }

    return $size;
  }

  /**
   * Compares the length of two paths and returns an integer indicating their relative order.
   * @param string $a The first path to compare.
   * @param string $b The second path to compare.
   * @return int The result of the comparison.
   */
  private function longestPath(string $a, string $b) : string{
    return strlen($b) <=> strlen($a);
  }
  
  /**
   * Compares the length of two paths and returns an integer indicating their relative order.
   * @param string $a The first path to compare.
   * @param string $b The second path to compare.
   * @return int The result of the comparison.
   */
  private function shortestPath(string $a, string $b) : string{
    return strlen($a) <=> strlen($b);
  }
}