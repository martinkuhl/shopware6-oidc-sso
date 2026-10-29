<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Console;

use MartinKuhl\Sw6Oidc\Console\ExportOidcConfigCommand;
use MartinKuhl\Sw6Oidc\Service\Config\OidcConfigTransfer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

#[CoversClass(ExportOidcConfigCommand::class)]
final class ExportOidcConfigCommandTest extends TestCase
{
    private string $directory;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/sw6oidc-export-' . bin2hex(random_bytes(4));
        mkdir($this->directory);
    }

    protected function tearDown(): void
    {
        foreach (scandir($this->directory) ?: [] as $file) {
            $file = $this->directory . '/' . $file;

            if (is_file($file) || is_link($file)) {
                unlink($file);
            }
        }

        rmdir($this->directory);
    }

    public function testWritesAnOwnerOnlyFile(): void
    {
        $file = $this->directory . '/export.json';

        self::assertSame(Command::SUCCESS, $this->tester()->execute(['--output' => $file, '--plaintext' => true]));
        self::assertSame(0o600, fileperms($file) & 0o777);
        self::assertStringContainsString('"providers"', (string) file_get_contents($file));
    }

    public function testRefusesToOverwriteWithoutForce(): void
    {
        $file = $this->directory . '/export.json';
        file_put_contents($file, 'keep');

        $tester = $this->tester();

        self::assertSame(Command::FAILURE, $tester->execute(['--output' => $file]));
        self::assertSame('keep', file_get_contents($file));

        self::assertSame(Command::SUCCESS, $tester->execute(['--output' => $file, '--force' => true]));
        self::assertStringContainsString('"providers"', (string) file_get_contents($file));
    }

    public function testForceReplacesASymlinkInsteadOfFollowingIt(): void
    {
        $target = $this->directory . '/target.txt';
        $link = $this->directory . '/export.json';
        file_put_contents($target, 'untouched');
        symlink($target, $link);

        self::assertSame(Command::SUCCESS, $this->tester()->execute(['--output' => $link, '--force' => true]));
        self::assertSame('untouched', file_get_contents($target));
        self::assertFalse(is_link($link));
    }

    public function testExportFailureIsReported(): void
    {
        $transfer = $this->createStub(OidcConfigTransfer::class);
        $transfer->method('export')->willThrowException(new \RuntimeException('cannot be decrypted'));

        $tester = new CommandTester(new ExportOidcConfigCommand($transfer));

        self::assertSame(Command::FAILURE, $tester->execute(['--plaintext' => true]));
        self::assertStringContainsString('cannot be decrypted', $tester->getDisplay());
    }

    private function tester(): CommandTester
    {
        $transfer = $this->createStub(OidcConfigTransfer::class);
        $transfer->method('export')->willReturn(['version' => 1, 'providers' => []]);

        return new CommandTester(new ExportOidcConfigCommand($transfer));
    }
}
