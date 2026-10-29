<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security;

use MartinKuhl\Sw6Oidc\Core\Content\AccessControlRule\Sw6OidcAccessControlRuleCollection;
use MartinKuhl\Sw6Oidc\Core\Content\AccessControlRule\Sw6OidcAccessControlRuleDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\AccessControlRule\Sw6OidcAccessControlRuleEntity;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\AccessControlDeniedException;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Sorting\FieldSorting;

/**
 * Claims-based login gate: every sw6oidc_access_control_rule of the provider
 * must pass (AND, in sort_order); the first failing rule denies the login
 * with its own message. No rules configured = everyone allowed.
 *
 * Matching works on ClaimsNormalizer::flatten() output, list-aware. A
 * claim's *values* are its members when it has any — the values of its
 * numeric children (`groups.0`, `groups.1`, ...) plus the names of its
 * non-numeric children (Zitadel-style role object `roles.Engineering.orgId`
 * → `engineering`) — else its own scalar value:
 * - `eq`: any value equals the expected value;
 * - `neq`: the claim is present and no value equals it;
 * - `contains`: a member equals it; on a scalar, one of its whitespace- or
 *   comma-separated tokens does (exact token, never a substring, N-M11);
 * - `not_contains`: the claim is present and `contains` is false;
 * - `ends_with`: any value ends with the expected suffix;
 * - `email_domain`: any value is an email address whose domain is exactly
 *   the expected one (a leading `@` is ignored) — the safe way to restrict
 *   by domain;
 * - `exists`/`not_exists`: the key itself or any child key.
 * Negative operators (`neq`, `not_contains`) **deny** when the claim is
 * missing, so an omitted claim (group overage, ungranted scope) can never
 * skip a deny-list rule (N-M10). All comparisons are case-insensitive and
 * trimmed; booleans, "true"/"false" and 1/0 compare as equal. An unknown
 * operator fails closed.
 */
class Sw6OidcAccessControlEvaluator
{
    /**
     * @param EntityRepository<Sw6OidcAccessControlRuleCollection> $ruleRepository
     */
    public function __construct(
        private readonly EntityRepository $ruleRepository,
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * @param array<string, mixed> $flattenedClaims
     *
     * @throws AccessControlDeniedException
     */
    public function evaluate(string $providerId, array $flattenedClaims, Context $context): void
    {
        $criteria = (new Criteria())
            ->addFilter(new EqualsFilter('providerId', $providerId))
            ->addSorting(new FieldSorting('sortOrder', FieldSorting::ASCENDING));

        foreach ($this->ruleRepository->search($criteria, $context)->getEntities() as $rule) {
            if ($this->matches($rule, $flattenedClaims)) {
                continue;
            }

            $this->logger->warning('sw6oidc: login denied by access-control rule.', [
                'providerId' => $providerId,
                'ruleId' => $rule->getId(),
                'claimKey' => $rule->getClaimKey(),
                'operator' => $rule->getOperator(),
            ]);

            throw new AccessControlDeniedException($rule->getId(), $rule->getClaimKey(), $rule->getErrorMessage());
        }
    }

    /**
     * @param array<string, mixed> $flattenedClaims
     */
    public function matches(Sw6OidcAccessControlRuleEntity $rule, array $flattenedClaims): bool
    {
        $key = trim($rule->getClaimKey());
        $expected = $this->normalize($rule->getValue());
        $scalar = \array_key_exists($key, $flattenedClaims) ? $this->normalize($flattenedClaims[$key]) : null;
        $members = $this->members($key, $flattenedClaims);
        $values = $members !== [] ? $members : ($scalar !== null ? [$scalar] : []);

        return match ($rule->getOperator()) {
            Sw6OidcAccessControlRuleDefinition::OPERATOR_EXISTS => $values !== [],
            Sw6OidcAccessControlRuleDefinition::OPERATOR_NOT_EXISTS => $values === [],
            Sw6OidcAccessControlRuleDefinition::OPERATOR_EQ => $this->anyValue($values, $expected, $this->sameValue(...)),
            Sw6OidcAccessControlRuleDefinition::OPERATOR_NEQ => $values !== [] && $expected !== null && !$this->anyValue($values, $expected, $this->sameValue(...)),
            Sw6OidcAccessControlRuleDefinition::OPERATOR_CONTAINS => $this->containsClaim($scalar, $members, $expected),
            Sw6OidcAccessControlRuleDefinition::OPERATOR_NOT_CONTAINS => $values !== [] && $expected !== null && $expected !== ''
                && !$this->containsClaim($scalar, $members, $expected),
            Sw6OidcAccessControlRuleDefinition::OPERATOR_ENDS_WITH => $expected !== '' && $this->anyValue($values, $expected, str_ends_with(...)),
            Sw6OidcAccessControlRuleDefinition::OPERATOR_EMAIL_DOMAIN => $this->anyValue($values, $expected, $this->hasEmailDomain(...)),
            default => $this->unknownOperator($rule),
        };
    }

    /**
     * @param list<string> $values
     * @param callable(string, string): bool $predicate
     */
    private function anyValue(array $values, ?string $expected, callable $predicate): bool
    {
        if ($expected === null) {
            return false;
        }

        foreach ($values as $value) {
            if ($predicate($value, $expected)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<string> $members
     */
    private function containsClaim(?string $scalar, array $members, ?string $expected): bool
    {
        if ($expected === null || $expected === '') {
            return false;
        }

        if ($members !== []) {
            return $this->anyValue($members, $expected, $this->sameValue(...));
        }

        if ($scalar === null) {
            return false;
        }

        $tokens = preg_split('/[\s,]+/u', $scalar, -1, \PREG_SPLIT_NO_EMPTY) ?: [];

        return \in_array($expected, $tokens, true);
    }

    private function hasEmailDomain(string $value, string $expectedDomain): bool
    {
        $expectedDomain = ltrim($expectedDomain, '@');
        $at = strrpos($value, '@');

        if ($expectedDomain === '' || $at === false || filter_var($value, \FILTER_VALIDATE_EMAIL) === false) {
            return false;
        }

        return substr($value, $at + 1) === $expectedDomain;
    }
    /**
     * @param array<string, mixed> $flattenedClaims
     *
     * @return list<string>
     */
    private function members(string $key, array $flattenedClaims): array
    {
        $prefix = $key . '.';
        $members = [];

        foreach ($flattenedClaims as $flatKey => $value) {
            $flatKey = (string) $flatKey;

            if (!str_starts_with($flatKey, $prefix)) {
                continue;
            }

            $child = explode('.', substr($flatKey, \strlen($prefix)), 2);

            if (ctype_digit($child[0])) {
                // A list entry: only its own scalar value, not a nested object's leaves.
                if (!isset($child[1])) {
                    $normalized = $this->normalize($value);

                    if ($normalized !== null) {
                        $members[] = $normalized;
                    }
                }

                continue;
            }

            $members[] = mb_strtolower(trim($child[0]));
        }

        return array_values(array_unique($members));
    }

    private function unknownOperator(Sw6OidcAccessControlRuleEntity $rule): bool
    {
        $this->logger->error('sw6oidc: access-control rule has an unknown operator, denying (fail closed).', [
            'ruleId' => $rule->getId(),
            'operator' => $rule->getOperator(),
        ]);

        return false;
    }

    private function normalize(mixed $value): ?string
    {
        return match (true) {
            \is_bool($value) => $value ? 'true' : 'false',
            \is_int($value), \is_float($value) => (string) $value,
            \is_string($value) => mb_strtolower(trim($value)),
            default => null,
        };
    }

    private function sameValue(string $actual, string $expected): bool
    {
        if ($actual === $expected) {
            return true;
        }

        $actualBool = $this->booleanish($actual);

        return $actualBool !== null && $actualBool === $this->booleanish($expected);
    }

    private function booleanish(string $value): ?bool
    {
        return match ($value) {
            'true', '1' => true,
            'false', '0' => false,
            default => null,
        };
    }
}
