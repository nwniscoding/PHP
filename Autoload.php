<?php
use RecursiveIteratorIterator as RII;
use RecursiveDirectoryIterator as RDI;

/**
 * Autoload classes dynamically from specified directories.
 */
final class Autoload{
	/**
	 * Holds the mapping of class names to file paths.
	 * @var array<string, string>
	 */
	private static array $classes = [];

	/**
	 * Load all PHP classes from the specified folder.
	 *
	 * @param string $folder The folder to scan for PHP class files.
	 * @param string|null $prefix Optional prefix to append to classes.
	 * @return void
	 */
	public static function load(string $folder, ?string $prefix = null): void{
		if(!is_dir($folder))
			throw new RuntimeException("Folder not found: $folder");

		$prefix = $prefix ? trim(self::backslash($prefix), "\\") . "\\" : "";
		$dir_iterator = new RDI($folder, RDI::SKIP_DOTS);
		$iterator = new RII($dir_iterator);

		foreach($iterator as $file){
			$path = $file->getPathname();
			$class = self::backslash(trim(substr($path, strlen($folder), -4), '/\\'));

			self::$classes["$prefix$class"] = $path;
		}
	}

	/**
	 * Register the autoloader for a given class.
	 * 
	 * @param string $class The fully qualified class name.
	 * @return void
	 */
	public static function register(string $class): void{
		if(!array_key_exists($class, self::$classes)){
			throw new RuntimeException("Class not found: $class");
		}

		require_once self::$classes[$class];
	}

	/**
	 * Convert forward slashes to backslashes in a string.
	 *
	 * @param string $str The input string.
	 * @return string The modified string with backslashes.
	 */
	private static function backslash(string $str): string{
		return str_replace("/", "\\", $str);
	}
}

// This file should be in the library folder.
Autoload::load(__DIR__);

spl_autoload_register([Autoload::class, 'register']);