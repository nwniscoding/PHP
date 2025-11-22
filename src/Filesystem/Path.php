<?php
namespace nwniscoding\Filesystem;

final class Path{
	/**
	 * Normalize a file system path.
	 * @param string $path The path to normalize.
	 * @return string The normalized path.
	 */
	public static function normalize(string $path): string{
		$path = strtr($path, "\\", "/");
		$absolute = $path !== "" && $path[0] === "/";
		$stack = [];

		foreach(explode("/", $path) as $part){
			if($part === "" || $part === ".") continue;

			if($part === ".."){
				if(!empty($stack)) array_pop($stack);

				continue;
			}
			
			$stack[] = $part;
		}

		$result = implode("/", $stack);

		if($absolute) $result = "/$result";

		return $result === "" ? "/" : $result;
	}

	/**
	 * Check if the path is relative.
	 * @param string $path The input file path
	 * @return bool True if the path is absolute, false otherwise.
	 */
	public static function isAbsolute(string $path): bool{
		return $path !== "" && $path[0] === "/";
	}

	/**
	 * Check if the path is relative.
	 * @param string $path The input file path
	 * @return bool True if the path is relative, false otherwise.
	 */
	public static function isRelative(string $path): bool{
		return !self::isAbsolute($path);
	}

	/**
	 * Get the directory name from a file path.
	 * @param string $path The input file path
	 * @return string The directory name
	 */
	public static function dirname(string $path): string{
		$path = self::normalize($path);
		$pos = strrpos($path, "/");

		if($pos === false) return ".";
		if($pos === 0) return "/";

		return substr($path, 0, $pos);
	}

	/**
	 * Get the base name from a file path.
	 * @param string $path The input file path
	 * @return string The base name
	 */
	public static function basename(string $path): string{
		return basename(self::normalize($path));
	}

	/**
	 * Get the file extension from a file name.
	 * @param string $filename The input file name
	 * @return string The file extension
	 */
	public static function extension(string $filename): string{
		$pos = strrpos($filename, ".");

		return $pos === false ? "" : substr($filename, $pos + 1);
	}

	/**
	 * Split a file path into its components.
	 * @param string $path The input file path
	 * @return array The path components
	 */
	public static function split(string $path): array{
		$path = trim(self::normalize($path), "/");
		return $path === "" ? [] : explode("/", $path);
	}

	/**
	 * Join multiple path components into a single path.
	 * @param string ...$parts The path components
	 * @return string The joined path
	 */
	public static function join(string ...$parts): string{
		return self::normalize(join("/", $parts));
	}

	/**
	 * Check if the given path is a file.
	 * @param string $path The input file path
	 * @return bool True if the path is a file, false otherwise.
	 */
	public static function isFile(string $path): bool{
		return is_file($path);
	}

	/**
	 * Check if the given path is a directory.
	 * @param string $path The input file path
	 * @return bool True if the path is a directory, false otherwise.
	 */
	public static function isDir(string $path): bool{
		return is_dir($path);
	}

	/**
	 * Check if the given path exists.
	 * @param string $path The input file path
	 * @return bool True if the path exists, false otherwise.
	 */
	public static function exists(string $path): bool{
		return file_exists($path);
	}

	/**
	 * Create a directory at the given path.
	 * @param string $path The input file path
	 * @param int $mode The permissions mode (default: 0644)
	 * @return bool True on success, false on failure.
	 */
	public static function mkdir(string $path, int $mode = 0644): bool{
		if(file_exists($path)) return true;

		return mkdir($path, $mode, true);
	}

	/**
	 * Remove a directory at the given path.
	 * @param string $path The input file path
	 * @return bool True on success, false on failure.
	 */
	public static function rmdir(string $path): bool{
		if(!is_dir($path)) return false;

		$items = array_diff(scandir($path), [".", ".."]);

		foreach($items as $item){
			$itemPath = self::join($path, $item);

			if(is_dir($itemPath)){
				if(!self::rmdir($itemPath)) return false;
			}
			else{
				if(!unlink($itemPath)) return false;
			}
		}

		return rmdir($path);
	}

	/**
	 * Delete a file at the given path.
	 * @param string $path The input file path
	 * @return bool True on success, false on failure.
	 */
	public static function unlink(string $path): bool{
		return is_file($path) ? unlink($path) : false;
	}

	/**
	 * Rename a file or directory.
	 * @param string $old The current file or directory path
	 * @param string $new The new file or directory path
	 * @return bool True on success, false on failure.
	 */
	public static function rename(string $old, string $new): bool{
		return rename($old, $new);
	}

	/**
	 * Copy a file or directory.
	 * @param string $from The source file or directory path
	 * @param string $to The destination file or directory path
	 * @return bool True on success, false on failure.
	 */
	public static function copy(string $from, string $to): bool{
		if(!file_exists($from)) return false;

		if(is_file($from)){
			$dir = dirname($to);

			if(!is_dir($dir) && !mkdir($dir, 0777, true)) return false;

			return copy($from, $to);
		}

		if(is_dir($from)){
			if(!is_dir($to) && !mkdir($to, 0777, true)) return false;

			foreach(array_diff(scandir($from), ['.', '..']) as $item){
				$src = "$from/$item";
				$dst = "$to/$item";

				if(!self::copy($src, $dst)) return false;
			}

			return true;
		}

		return false;
	}
}