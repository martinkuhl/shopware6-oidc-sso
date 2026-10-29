<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Logging;

use MartinKuhl\Sw6Oidc\Service\Logging\SensitiveDataProcessor;
use Monolog\Level;
use Monolog\LogRecord;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(SensitiveDataProcessor::class)]
final class SensitiveDataProcessorTest extends TestCase
{
    /**
     * @return iterable<string, array{string}>
     */
    public static function sensitiveKeys(): iterable
    {
        foreach (['client_secret', 'clientSecret', 'idToken', 'id_token', 'logout_token', 'refreshToken', 'code_verifier', 'state', 'nonce', 'sw6oidc_nonce', 'secret', 'Authorization', 'healthAlertWebhookUrl', 'webhook_url', 'contextToken', 'sessionKey', 'jwt', 'cookie', 'apiKey', 'idpAccessToken'] as $key) {
            yield $key => [$key];
        }
    }

    #[DataProvider('sensitiveKeys')]
    public function testSensitiveKeyVariantsAreMasked(string $key): void
    {
        $context = $this->process('m', [$key => 'value', 'nested' => [$key => 'value']])->context;

        self::assertSame('***MASKED***', $context[$key]);
        self::assertSame('***MASKED***', $context['nested'][$key]);
    }

    public function testOrdinaryKeysAndEmptyValuesAreKept(): void
    {
        $context = $this->process('m', ['providerId' => 'p1', 'state' => ''])->context;

        self::assertSame(['providerId' => 'p1', 'state' => ''], $context);
    }

    public function testQueryParametersAreScrubbedInMessagesAndStrings(): void
    {
        $record = $this->process(
            'Redirecting to https://shop.example/callback?code=abc123&state=xyz&foo=bar',
            ['url' => 'https://idp.example/logout?id_token_hint=eyJ.hint.sig&post_logout_redirect_uri=https://shop.example/'],
        );

        self::assertStringNotContainsString('abc123', $record->message);
        self::assertStringNotContainsString('xyz', $record->message);
        self::assertStringContainsString('foo=bar', $record->message);
        self::assertStringNotContainsString('eyJ.hint.sig', $record->context['url']);
        self::assertStringContainsString('post_logout_redirect_uri=', $record->context['url']);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function secretsInStrings(): iterable
    {
        yield 'parameter at the start' => ['code=abc12345&x=1', 'abc12345'];
        yield 'semicolon list' => ['x=1;state=abc12345', 'abc12345'];
        yield 'url-encoded inside another url' => ['https://shop/x?r=https%3A%2F%2Fa%2Fcb%3Fcode%3Dabc12345%26y%3D1', 'abc12345'];
        yield 'json body' => ['{"access_token":"abc12345","token_type":"Bearer"}', 'abc12345'];
        yield 'json body with spaces' => ['{"client_secret" : "abc12345"}', 'abc12345'];
        yield 'bearer header' => ['Authorization: Bearer abc12345xyz', 'abc12345xyz'];
        yield 'basic header' => ['Authorization: Basic YWxpY2U6c2VjcmV0', 'YWxpY2U6c2VjcmV0'];
        yield 'bare jwt' => ['token eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl here', 'eyJzdWIiOi'];
    }

    #[DataProvider('secretsInStrings')]
    public function testSecretsInsideStringsAreMasked(string $input, string $secret): void
    {
        $record = $this->process($input, ['detail' => $input]);

        self::assertStringNotContainsString($secret, $record->message);
        self::assertStringNotContainsString($secret, $record->context['detail']);
        self::assertStringContainsString('***MASKED***', $record->message);
    }

    public function testNonStringValuesUnderSensitiveKeysAreMasked(): void
    {
        $context = $this->process('m', ['code' => 12345678, 'token' => ['a' => 'b'], 'hasNonce' => true, 'nonce' => false])->context;

        self::assertSame('***MASKED***', $context['code']);
        self::assertSame('***MASKED***', $context['token']);
        self::assertTrue($context['hasNonce']);
        self::assertFalse($context['nonce'], 'booleans reveal nothing');
    }

    public function testExceptionsAreReducedToAScrubbedMessage(): void
    {
        $context = $this->process('m', ['exception' => new \RuntimeException('GET https://idp/x?access_token=abc12345 failed')])->context;

        self::assertSame('RuntimeException: GET https://idp/x?access_token=***MASKED*** failed', $context['exception']);
    }

    public function testOrdinaryTextIsKept(): void
    {
        $record = $this->process('Provider p1 encoded=yes, decoder=x', ['tokenCount' => 3]);

        self::assertSame('Provider p1 encoded=yes, decoder=x', $record->message);
        self::assertSame(3, $record->context['tokenCount']);
    }

    /**
     * @param array<string, mixed> $context
     */
    private function process(string $message, array $context): LogRecord
    {
        return (new SensitiveDataProcessor())(new LogRecord(new \DateTimeImmutable(), 'sw6oidc', Level::Warning, $message, $context));
    }
}
