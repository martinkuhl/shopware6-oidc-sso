<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Console;

use MartinKuhl\Sw6Oidc\Service\Config\OidcConfigTransfer;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\Uuid\Uuid;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(
    name: 'sw6oidc:config:export',
    description: 'Export OIDC provider configuration (incl. attribute and role mappings) as JSON',
)]
class ExportOidcConfigCommand extends Command
{
    public function __construct(private readonly OidcConfigTransfer $transfer)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption('provider-id', null, InputOption::VALUE_REQUIRED, 'Export only this provider')
            ->addOption('output', 'o', InputOption::VALUE_REQUIRED, 'Write to this file instead of stdout')
            ->addOption('keep-encrypted', null, InputOption::VALUE_NONE, 'Include the client secret as its encrypted envelope (importable only where APP_SECRET is identical)')
            ->addOption('plaintext', null, InputOption::VALUE_NONE, 'Include the client secret in PLAINTEXT (insecure — treat the file as a credential)')
            ->addOption('force', 'f', InputOption::VALUE_NONE, 'Overwrite the --output file if it already exists');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $errorOutput = $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;

        if ($input->getOption('keep-encrypted') && $input->getOption('plaintext')) {
            $errorOutput->writeln('<error>--keep-encrypted and --plaintext are mutually exclusive.</error>');

            return self::INVALID;
        }

        $providerId = $input->getOption('provider-id');

        if ($providerId !== null && (!\is_string($providerId) || !Uuid::isValid($providerId))) {
            $errorOutput->writeln('<error>--provider-id must be a valid id.</error>');

            return self::INVALID;
        }

        $secretMode = match (true) {
            (bool) $input->getOption('plaintext') => OidcConfigTransfer::SECRET_PLAINTEXT,
            (bool) $input->getOption('keep-encrypted') => OidcConfigTransfer::SECRET_ENCRYPTED,
            default => OidcConfigTransfer::SECRET_OMIT,
        };

        if ($secretMode === OidcConfigTransfer::SECRET_PLAINTEXT) {
            $errorOutput->writeln('<comment>Warning: the export contains client secrets in plaintext. Treat it as a credential and delete it after use.</comment>');
        }

        try {
            $export = $this->transfer->export($providerId, $secretMode, Context::createCLIContext());
        } catch (\RuntimeException $exception) {
            $errorOutput->writeln(sprintf('<error>%s</error>', $exception->getMessage()));

            return self::FAILURE;
        }

        $json = json_encode($export, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_THROW_ON_ERROR) . "\n";

        $file = $input->getOption('output');

        if (\is_string($file) && $file !== '') {
            $error = $this->writeExclusive($file, $json, (bool) $input->getOption('force'));

            if ($error !== null) {
                $errorOutput->writeln(sprintf('<error>%s</error>', $error));

                return self::FAILURE;
            }

            $errorOutput->writeln(sprintf('Exported %d provider(s) to %s.', \count($export['providers']), $file));

            return self::SUCCESS;
        }

        $output->write($json, false, OutputInterface::OUTPUT_RAW);

        return self::SUCCESS;
    }

    /**
     * The export can hold secrets (N-L9): create the file owner-only with
     * O_EXCL semantics (never through an existing file or symlink), and only
     * replace an existing file with --force — by unlinking it first, so a
     * symlink is removed rather than followed.
     */
    private function writeExclusive(string $file, string $contents, bool $force): ?string
    {
        if (file_exists($file) || is_link($file)) {
            if (!$force) {
                return sprintf('"%s" already exists; pass --force to overwrite it.', $file);
            }

            if (!@unlink($file)) {
                return sprintf('Could not replace "%s".', $file);
            }
        }

        $previousUmask = umask(0o077);

        try {
            $handle = @fopen($file, 'x');
        } finally {
            umask($previousUmask);
        }

        if ($handle === false) {
            return sprintf('Could not create "%s".', $file);
        }

        try {
            @chmod($file, 0o600);

            if (fwrite($handle, $contents) !== \strlen($contents)) {
                return sprintf('Could not write "%s".', $file);
            }
        } finally {
            fclose($handle);
        }

        return null;
    }
}
