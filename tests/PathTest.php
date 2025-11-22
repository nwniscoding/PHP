<?php
use PHPUnit\Framework\TestCase;
use nwniscoding\Filesystem\Path;

final class PathTest extends TestCase{
	private string $temp;

	protected function setUp(): void{
		$this->temp = sys_get_temp_dir()."/path_test_".uniqid();
		mkdir($this->temp);
	}

	protected function tearDown(): void{
		if(is_dir($this->temp)) Path::rmdir($this->temp);
	}

	public function testNormalize(): void{
		$this->assertSame('/a/b/c', Path::normalize('/a//b/./c'));
		$this->assertSame('/a', Path::normalize('/a/b/..'));
		$this->assertSame('/', Path::normalize('/'));
		$this->assertSame('/', Path::normalize(''));
		$this->assertSame('a/b', Path::normalize('a//b'));
		$this->assertSame('a', Path::normalize('./a'));
		$this->assertSame('/', Path::normalize('/../..'));
		$this->assertSame('/a/b', Path::normalize('\\a\\b'));
	}

	public function testIsAbsolute(): void{
		$this->assertTrue(Path::isAbsolute('/a/b'));
		$this->assertFalse(Path::isAbsolute('a/b'));
	}

	public function testIsRelative(): void{
		$this->assertTrue(Path::isRelative('a/b'));
		$this->assertFalse(Path::isRelative('/a/b'));
	}

	public function testDirname(): void{
		$this->assertSame('/', Path::dirname('/a'));
		$this->assertSame('/a', Path::dirname('/a/b'));
		$this->assertSame('.', Path::dirname('a'));
	}

	public function testBasename(): void{
		$this->assertSame('b', Path::basename('/a/b'));
		$this->assertSame('file.txt', Path::basename('/x/y/file.txt'));
		$this->assertSame('a', Path::basename('a'));
	}

	public function testExtension(): void{
		$this->assertSame('txt', Path::extension('file.txt'));
		$this->assertSame('gz', Path::extension('archive.tar.gz'));
		$this->assertSame('', Path::extension('noext'));
	}

	public function testSplit(): void{
		$this->assertSame(['a', 'b', 'c'], Path::split('/a/b/c'));
		$this->assertSame([], Path::split('/'));
		$this->assertSame([], Path::split(''));
	}

	public function testJoin(): void{
		$this->assertSame('/a/b/c', Path::join('/a', 'b', 'c'));
		$this->assertSame('a/b', Path::join('a', 'b'));
	}

	public function testMkdirAndExists(): void{
		$dir = $this->temp . '/sub';
		$this->assertTrue(Path::mkdir($dir));
		$this->assertTrue(Path::exists($dir));
		$this->assertTrue(Path::isDir($dir));
	}

	public function testFileCreationAndUnlink(): void{
		$file = $this->temp . '/test.txt';
		file_put_contents($file, 'hello');

		$this->assertTrue(Path::isFile($file));
		$this->assertTrue(Path::unlink($file));
		$this->assertFalse(file_exists($file));
	}

	public function testCopyFile(): void{
		$src = $this->temp . '/a.txt';
		$dst = $this->temp . '/b.txt';
		file_put_contents($src, 'hello');

		$this->assertTrue(Path::copy($src, $dst));
		$this->assertTrue(is_file($dst));
		$this->assertSame('hello', file_get_contents($dst));
	}

	public function testCopyDirectoryRecursive(): void{
		$srcDir = $this->temp . '/src';
		$dstDir = $this->temp . '/dst';

		mkdir($srcDir);
		file_put_contents($srcDir . '/a.txt', 'A');
		mkdir($srcDir . '/sub');
		file_put_contents($srcDir . '/sub/b.txt', 'B');

		$this->assertTrue(Path::copy($srcDir, $dstDir));

		$this->assertTrue(file_exists($dstDir . '/a.txt'));
		$this->assertTrue(file_exists($dstDir . '/sub/b.txt'));

		$this->assertSame('A', file_get_contents($dstDir . '/a.txt'));
		$this->assertSame('B', file_get_contents($dstDir . '/sub/b.txt'));
	}

	public function testRmdirRecursive(): void{
		$dir = $this->temp . '/nested';
		mkdir($dir);
		mkdir($dir . '/x');
		file_put_contents($dir . '/x/y.txt', 'test');

		$this->assertTrue(Path::rmdir($dir));
		$this->assertFalse(file_exists($dir));
	}
}