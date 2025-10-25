<?php
namespace SQL;

use Closure;

/**
 * Interface for database configuration classes.
 */
interface ConfigInterface{
	/**
	 * Get the type of database configuration.
	 *
	 * @return string The type of database (e.g., "mysql").
	 */
	public function getType(): string;

	/**
	 * Get the Data Source Name (DSN) string for the database connection.
	 *
	 * @return string The DSN string.
	 */
	public function getDSN(): string;

	/**
	 * Apply hidden configuration values to a given function.
	 * 
	 * @param callable(array<string, mixed>): void $fn The function or method to apply the credentials to.
	 */
	public function apply(Closure|array $fn): void;
}