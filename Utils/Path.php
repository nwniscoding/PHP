<?php
namespace Utils;

/**
 * Utility class for handling file paths.
 */
final class Path{
	private function __construct(){}

	public static function normalize(string $path): string{
		$path = str_replace("\\","/", $path);
		$parts = explode("/", $path);
		$stack = [];

		foreach($parts as $part){
			if($part === "" || $part === "."){
				continue;
			}

			if($part === ".."){
				array_pop($stack);
			}
			
			else{
				$stack[] = $part;
			}
		}

		$result = implode("/", $stack);

		if(isset($path[0]) && $path[0] === "/"){
			$result = "/$result";
		}

		return $result === "" ? "/" : $result;
	}

	/**
	 * Checks if a path is absolute.
	 * 
	 * @param string $path The input file path.
	 * @return bool True if the path is absolute, false otherwise.
	 */
	public static function isAbsolute(string $path): bool{
		if($path === '') return false;

		return $path[0] === '/';
	}

	/**
	 * Checks if a path is relative.
	 * 
	 * @param string $path The input file path.
	 * @return bool True if the path is relative, false otherwise.
	 */
	public static function isRelative(string $path): bool{
		return !self::isAbsolute($path);
	}

	/**
	 * Gets the directory name from a file path.
	 * 
	 * @param string $path The input file path.
	 * @return string The directory name.
	 */
	public static function dirname(string $path): string{
		$path = self::normalize($path);
			
		return rtrim(substr($path, 0, strrpos($path, '/')) ?: '/', '/');
	}

	/**
	 * Gets the base name (file name with extension) from a file path.
	 * 
	 * @param string $path The input file path.
	 * @return string The base name.
	 */
	public static function basename(string $path): string{
		return basename(self::normalize($path));
	}

	/**
	 * Gets the file extension from a file name.
	 * 
	 * @param string $filename The input file name.
	 * @return string The file extension, or an empty string if none exists.
	 */
	public static function extension(string $filename): string{
		$pos = strrpos($filename, '.');

		if($pos === false) return '';

		return substr($filename, $pos + 1);
	}

	/**
	 * Splits a file path into its components.
	 * 
	 * @param string $path The input file path.
	 * @return array An array of path components.
	 */
	public static function parts(string $path): array{
		$path = trim(self::normalize($path), '/');

		return $path === '' ? [] : explode('/', $path);
	}

	/**
	 * Joins multiple path segments into a single normalized path.
	 * 
	 * @param string ...$paths The path segments to join.
	 * @return string The joined and normalized path.
	 */
	public static function join(string ...$paths): string{
		return self::normalize(implode('/', $paths));
	}

	/**
	 * Checks if the given path is a file.
	 * 
	 * @param string $path The input file path.
	 * @return bool True if the path is a file, false otherwise.
	 */
	public static function isFile(string $path): bool{
		return is_file($path);
	}

	/**
	 * Checks if the given path is a directory.
	 * 
	 * @param string $path The input file path.
	 * @return bool True if the path is a directory, false otherwise.
	 */
	public static function isDir(string $path): bool{
		return is_dir($path);
	}

	/**
	 * Checks if the given path exists.
	 * 
	 * @param string $path The input file path.
	 * @return bool True if the path exists, false otherwise.
	 */
	public static function exists(string $path): bool{
		return file_exists($path);
	}

	/**
	 * Creates a directory at the specified path, including any necessary parent directories.
	 * 
	 * @param string $path The directory path to create.
	 * @param int $mode The permissions mode (default is 0777).
	 * @return bool True on success, false on failure.
	 */
	public static function mkdir(string $path, int $mode = 0777): bool{
		if(file_exists($path)) return true;
		return mkdir($path, $mode, true);
	}

	/**
	 * Recursively removes a directory and its contents.
	 * 
	 * @param string $path The directory path to remove.
	 * @return bool True on success, false on failure.
	 */
	public static function rmdir(string $path): bool{
		if(!is_dir($path)) return false;
		
		$items = array_diff(scandir($path), ['.', '..']);

		foreach($items as $item){
			$item_path = self::join($path, $item);
				
			if(is_dir($item_path)) self::rmdir($item_path);
			else unlink($item_path);
		}

		return rmdir($path);
	}

	/**
	 * Deletes a file at the specified path.
	 * 
	 * @param string $path The file path to delete.
	 * @return bool True on success, false on failure.
	 */
	public static function unlink(string $path): bool{
		return is_file($path) ? unlink($path) : false;
	}

	/**
	 * Renames or moves a file or directory.
	 * 
	 * @param string $old The current file or directory path.
	 * @param string $new The new file or directory path.
	 * @return bool True on success, false on failure.
	 */
	public static function rename(string $old, string $new): bool{
		return rename($old, $new);
	}

	/**
	 * Recursively copies a file or directory to a new location.
	 * 
	 * @param string $from The source file or directory path.
	 * @param string $to The destination file or directory path.
	 * @return bool True on success, false on failure.
	 */
	public static function copy(string $from, string $to): bool{
		if(is_dir($from)){
			if(!self::mkdir($to)) return false;

			$items = array_diff(scandir($from), ['.', '..']);

			foreach($items as $item){
				$item_from = self::join($from, $item);
				$item_to = self::join($to, $item);

				if(is_dir($item_from)){
					self::copy($item_from, $item_to);
				}
				else{
					copy($item_from, $item_to);
				}
			}

			return true;
		}
		else{
			return copy($from, $to);
		}
	}
}