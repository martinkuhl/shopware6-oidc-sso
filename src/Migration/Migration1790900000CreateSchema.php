<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

/**
 * The plugin's whole schema. Every table is created only if it doesn't exist
 * yet, so the step is a no-op on an install that already has it.
 *
 * The plugin has a single schema migration on purpose: it is in development
 * and has no installs to upgrade. Until a first release, schema changes edit
 * this file, and an existing development install is altered by hand or
 * reinstalled (sw6oidc:config:export, uninstall, install, import).
 */
class Migration1790900000CreateSchema extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1790900000;
    }

    public function update(Connection $connection): void
    {
        foreach (self::statements() as $statement) {
            $connection->executeStatement($statement);
        }
    }

    public function updateDestructive(Connection $connection): void
    {
    }

    /**
     * @return list<string>
     */
    public static function statements(): array
    {
        return [
            <<<'SQL'
                CREATE TABLE IF NOT EXISTS `sw6oidc_provider` (
                    `id` BINARY(16) NOT NULL,
                    `app_name` VARCHAR(255) NOT NULL,
                    `display_name` VARCHAR(255) NULL,
                    `client_id` VARCHAR(255) NOT NULL,
                    `client_secret` VARCHAR(2048) NULL,
                    `authorize_endpoint` VARCHAR(1024) NULL,
                    `access_token_endpoint` VARCHAR(1024) NULL,
                    `token_endpoint_auth_method` VARCHAR(32) NOT NULL DEFAULT 'client_secret_basic',
                    `user_info_endpoint` VARCHAR(1024) NULL,
                    `end_session_endpoint` VARCHAR(1024) NULL,
                    `logout_style` VARCHAR(32) NOT NULL DEFAULT 'standard',
                    `post_logout_url` VARCHAR(1024) NULL,
                    `revocation_endpoint` VARCHAR(1024) NULL,
                    `revocation_endpoint_auth_method` VARCHAR(32) NOT NULL DEFAULT 'client_secret_basic',
                    `jwks_endpoint` VARCHAR(1024) NULL,
                    `issuer` VARCHAR(1024) NULL,
                    `well_known_config_url` VARCHAR(1024) NULL,
                    `scope` VARCHAR(512) NOT NULL DEFAULT 'openid profile email',
                    `pkce_flow` VARCHAR(16) NOT NULL DEFAULT 'S256',
                    `claims_parameter_supported` TINYINT(1) NOT NULL DEFAULT 0,
                    `base64_claims` JSON NULL,
                    `public_client` TINYINT(1) NOT NULL DEFAULT 0,
                    `group_attribute` VARCHAR(255) NOT NULL DEFAULT 'groups',
                    `auto_create_customer` TINYINT(1) NOT NULL DEFAULT 1,
                    `auto_create_admin` TINYINT(1) NOT NULL DEFAULT 0,
                    `disable_non_oidc_admin_login` TINYINT(1) NOT NULL DEFAULT 0,
                    `disable_non_oidc_customer_login` TINYINT(1) NOT NULL DEFAULT 0,
                    `show_customer_link` TINYINT(1) NOT NULL DEFAULT 1,
                    `show_admin_link` TINYINT(1) NOT NULL DEFAULT 1,
                    `is_active` TINYINT(1) NOT NULL DEFAULT 1,
                    `login_type` VARCHAR(16) NOT NULL DEFAULT 'both',
                    `sort_order` INT NOT NULL DEFAULT 0,
                    `sync_customer_profile_on_sso` TINYINT(1) NOT NULL DEFAULT 0,
                    `sync_customer_address_on_sso` TINYINT(1) NOT NULL DEFAULT 0,
                    `sync_customer_group_on_sso` TINYINT(1) NOT NULL DEFAULT 0,
                    `sync_admin_profile_on_sso` TINYINT(1) NOT NULL DEFAULT 0,
                    `sync_admin_role_on_sso` TINYINT(1) NOT NULL DEFAULT 0,
                    `allow_superadmin_group_mapping` TINYINT(1) NOT NULL DEFAULT 0,
                    `revoke_superadmin_on_sso` TINYINT(1) NOT NULL DEFAULT 0,
                    `require_email_verified` TINYINT(1) NOT NULL DEFAULT 1,
                    `link_existing_accounts` TINYINT(1) NOT NULL DEFAULT 0,
                    `frontchannel_admin_logout` TINYINT(1) NOT NULL DEFAULT 0,
                    `http_timeout` SMALLINT NOT NULL DEFAULT 30,
                    `jwks_cache_ttl` INT NOT NULL DEFAULT 86400,
                    `last_test_status` VARCHAR(16) NULL,
                    `last_test_at` DATETIME(3) NULL,
                    `last_test_claims` JSON NULL,
                    `default_customer_group_id` BINARY(16) NULL,
                    `default_acl_role_id` BINARY(16) NULL,
                    `health_alert_webhook_url` VARCHAR(2048) NULL,
                    `health_alert_failure_threshold` INT NOT NULL DEFAULT 0,
                    `health_alert_notify_on_recovery` TINYINT(1) NOT NULL DEFAULT 0,
                    `health_alert_consecutive_failures` INT NOT NULL DEFAULT 0,
                    `health_alert_last_status` VARCHAR(16) NULL,
                    `health_alert_last_checked_at` DATETIME(3) NULL,
                    `health_alert_first_failure_at` DATETIME(3) NULL,
                    `health_alert_last_notified_at` DATETIME(3) NULL,
                    `created_at` DATETIME(3) NOT NULL,
                    `updated_at` DATETIME(3) NULL,
                    PRIMARY KEY (`id`),
                    UNIQUE KEY `uniq.sw6oidc_provider.app_name` (`app_name`),
                    KEY `fk.sw6oidc_provider.default_customer_group_id` (`default_customer_group_id`),
                    KEY `fk.sw6oidc_provider.default_acl_role_id` (`default_acl_role_id`),
                    CONSTRAINT `fk.sw6oidc_provider.default_acl_role_id` FOREIGN KEY (`default_acl_role_id`)
                        REFERENCES `acl_role` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
                    CONSTRAINT `fk.sw6oidc_provider.default_customer_group_id` FOREIGN KEY (`default_customer_group_id`)
                        REFERENCES `customer_group` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                SQL,
            <<<'SQL'
                CREATE TABLE IF NOT EXISTS `sw6oidc_attribute_mapping` (
                    `id` BINARY(16) NOT NULL,
                    `provider_id` BINARY(16) NOT NULL,
                    `attribute_type` VARCHAR(64) NOT NULL,
                    `attribute_name` VARCHAR(255) NOT NULL,
                    `transform_function` VARCHAR(32) NULL,
                    `transform_params` JSON NULL,
                    `created_at` DATETIME(3) NOT NULL,
                    `updated_at` DATETIME(3) NULL,
                    PRIMARY KEY (`id`),
                    UNIQUE KEY `uniq.sw6oidc_attribute_mapping.provider_type` (`provider_id`, `attribute_type`),
                    CONSTRAINT `fk.sw6oidc_attribute_mapping.provider_id` FOREIGN KEY (`provider_id`)
                        REFERENCES `sw6oidc_provider` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                SQL,
            <<<'SQL'
                CREATE TABLE IF NOT EXISTS `sw6oidc_role_mapping` (
                    `id` BINARY(16) NOT NULL,
                    `provider_id` BINARY(16) NOT NULL,
                    `mapping_type` VARCHAR(32) NOT NULL,
                    `oidc_group` VARCHAR(255) NOT NULL,
                    `acl_role_id` BINARY(16) NULL,
                    `customer_group_id` BINARY(16) NULL,
                    `sort_order` INT NOT NULL DEFAULT 0,
                    `created_at` DATETIME(3) NOT NULL,
                    `updated_at` DATETIME(3) NULL,
                    PRIMARY KEY (`id`),
                    KEY `fk.sw6oidc_role_mapping.provider_id` (`provider_id`),
                    KEY `fk.sw6oidc_role_mapping.acl_role_id` (`acl_role_id`),
                    KEY `fk.sw6oidc_role_mapping.customer_group_id` (`customer_group_id`),
                    CONSTRAINT `fk.sw6oidc_role_mapping.acl_role_id` FOREIGN KEY (`acl_role_id`)
                        REFERENCES `acl_role` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
                    CONSTRAINT `fk.sw6oidc_role_mapping.customer_group_id` FOREIGN KEY (`customer_group_id`)
                        REFERENCES `customer_group` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
                    CONSTRAINT `fk.sw6oidc_role_mapping.provider_id` FOREIGN KEY (`provider_id`)
                        REFERENCES `sw6oidc_provider` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                SQL,
            <<<'SQL'
                CREATE TABLE IF NOT EXISTS `sw6oidc_access_control_rule` (
                    `id` BINARY(16) NOT NULL,
                    `provider_id` BINARY(16) NOT NULL,
                    `claim_key` VARCHAR(255) NOT NULL,
                    `operator` VARCHAR(16) NOT NULL,
                    `value` VARCHAR(1024) NULL,
                    `error_message` VARCHAR(1024) NULL,
                    `sort_order` INT NOT NULL DEFAULT 0,
                    `created_at` DATETIME(3) NOT NULL,
                    `updated_at` DATETIME(3) NULL,
                    PRIMARY KEY (`id`),
                    KEY `fk.sw6oidc_access_control_rule.provider_id` (`provider_id`),
                    CONSTRAINT `fk.sw6oidc_access_control_rule.provider_id` FOREIGN KEY (`provider_id`)
                        REFERENCES `sw6oidc_provider` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                SQL,
            // `issuer` and `sub` compare byte-exactly. The identity key holds
            // issuer + subject + the sales channel of a channel-bound customer
            // (`binding_scope`, else 16 zero bytes = global).
            <<<'SQL'
                CREATE TABLE IF NOT EXISTS `sw6oidc_user_provider` (
                    `id` BINARY(16) NOT NULL,
                    `user_type` VARCHAR(16) NOT NULL,
                    `user_id` BINARY(16) NOT NULL,
                    `provider_id` BINARY(16) NOT NULL,
                    `issuer` VARCHAR(2048) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
                    `issuer_hash` CHAR(64) NOT NULL,
                    `sub` VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
                    `binding_scope` BINARY(16) NOT NULL DEFAULT 0x00000000000000000000000000000000,
                    `created_at` DATETIME(3) NOT NULL,
                    `updated_at` DATETIME(3) NULL,
                    PRIMARY KEY (`id`),
                    UNIQUE KEY `uniq.sw6oidc_user_provider.user` (`user_type`, `user_id`),
                    UNIQUE KEY `uniq.sw6oidc_user_provider.identity` (`provider_id`, `user_type`, `issuer_hash`, `sub`, `binding_scope`),
                    KEY `fk.sw6oidc_user_provider.provider_id` (`provider_id`),
                    CONSTRAINT `fk.sw6oidc_user_provider.provider_id` FOREIGN KEY (`provider_id`)
                        REFERENCES `sw6oidc_provider` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                SQL,
            <<<'SQL'
                CREATE TABLE IF NOT EXISTS `sw6oidc_passkey_credential` (
                    `id` BINARY(16) NOT NULL,
                    `user_type` VARCHAR(16) NOT NULL,
                    `user_id` BINARY(16) NOT NULL,
                    `credential_id` VARCHAR(1400) NOT NULL,
                    `credential_id_hash` CHAR(64) NOT NULL,
                    `public_key` LONGTEXT NOT NULL,
                    `sign_count` INT UNSIGNED NOT NULL DEFAULT 0,
                    `user_handle` VARCHAR(255) NOT NULL,
                    `nickname` VARCHAR(255) NULL,
                    `disabled_at` DATETIME(3) NULL,
                    `created_at` DATETIME(3) NOT NULL,
                    `updated_at` DATETIME(3) NULL,
                    PRIMARY KEY (`id`),
                    UNIQUE KEY `uniq.sw6oidc_passkey_credential.credential_id_hash` (`credential_id_hash`),
                    KEY `idx.sw6oidc_passkey_credential.user` (`user_type`, `user_id`),
                    KEY `idx.sw6oidc_passkey_credential.user_handle` (`user_handle`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                SQL,
            <<<'SQL'
                CREATE TABLE IF NOT EXISTS `sw6oidc_session_activity` (
                    `id` BINARY(16) NOT NULL,
                    `provider_id` BINARY(16) NULL,
                    `user_type` VARCHAR(16) NOT NULL,
                    `user_id` BINARY(16) NOT NULL,
                    `sub` VARCHAR(255) NULL,
                    `sid` VARCHAR(255) NULL,
                    `login_method` VARCHAR(16) NOT NULL,
                    `session_key_hash` CHAR(64) NULL,
                    `registry_session_id` VARCHAR(64) NULL,
                    `passkey_credential_hash` CHAR(64) NULL,
                    `ip_address` VARCHAR(45) NULL,
                    `user_agent` VARCHAR(512) NULL,
                    `logged_in_at` DATETIME(3) NOT NULL,
                    `logged_out_at` DATETIME(3) NULL,
                    `logout_reason` VARCHAR(32) NULL,
                    `created_at` DATETIME(3) NOT NULL,
                    `updated_at` DATETIME(3) NULL,
                    PRIMARY KEY (`id`),
                    KEY `idx.sw6oidc_session_activity.user` (`user_type`, `user_id`),
                    KEY `idx.sw6oidc_session_activity.logged_in_at` (`logged_in_at`),
                    KEY `idx.sw6oidc_session_activity.session_key_hash` (`session_key_hash`),
                    KEY `idx.sw6oidc_session_activity.registry_session_id` (`registry_session_id`),
                    KEY `idx.sw6oidc_session_activity.passkey_credential_hash` (`passkey_credential_hash`),
                    KEY `fk.sw6oidc_session_activity.provider_id` (`provider_id`),
                    CONSTRAINT `fk.sw6oidc_session_activity.provider_id` FOREIGN KEY (`provider_id`)
                        REFERENCES `sw6oidc_provider` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                SQL,
            <<<'SQL'
                CREATE TABLE IF NOT EXISTS `sw6oidc_session` (
                    `id` CHAR(32) NOT NULL,
                    `provider_id` BINARY(16) NOT NULL,
                    `sub` VARCHAR(255) NOT NULL,
                    `sid` VARCHAR(255) NULL,
                    `user_type` VARCHAR(16) NOT NULL,
                    `user_id` BINARY(16) NOT NULL,
                    `session_key` TEXT NOT NULL,
                    `session_key_hash` CHAR(64) NOT NULL,
                    `device_hash` CHAR(64) NULL,
                    `sales_channel_id` BINARY(16) NULL,
                    `id_token` TEXT NULL,
                    `idp_access_token` TEXT NULL,
                    `idp_refresh_token` TEXT NULL,
                    `created_at` DATETIME(3) NOT NULL,
                    `expires_at` DATETIME(3) NOT NULL,
                    PRIMARY KEY (`id`),
                    KEY `idx.sw6oidc_session.provider_sid` (`provider_id`, `sid`),
                    KEY `idx.sw6oidc_session.provider_sub` (`provider_id`, `sub`),
                    KEY `idx.sw6oidc_session.user` (`user_type`, `user_id`),
                    KEY `idx.sw6oidc_session.session_key_hash` (`session_key_hash`),
                    KEY `idx.sw6oidc_session.expires_at` (`expires_at`),
                    CONSTRAINT `fk.sw6oidc_session.provider_id` FOREIGN KEY (`provider_id`)
                        REFERENCES `sw6oidc_provider` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                SQL,
            <<<'SQL'
                CREATE TABLE IF NOT EXISTS `sw6oidc_one_time_token` (
                    `key_hash` CHAR(64) NOT NULL,
                    `value` MEDIUMTEXT NOT NULL,
                    `expires_at` DATETIME(3) NOT NULL,
                    PRIMARY KEY (`key_hash`),
                    KEY `idx.sw6oidc_one_time_token.expires_at` (`expires_at`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                SQL,
            <<<'SQL'
                CREATE TABLE IF NOT EXISTS `sw6oidc_node_heartbeat` (
                    `hostname` VARCHAR(255) NOT NULL,
                    `last_seen_at` DATETIME(3) NOT NULL,
                    PRIMARY KEY (`hostname`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                SQL,
            <<<'SQL'
                CREATE TABLE IF NOT EXISTS `sw6oidc_managed_acl_role` (
                    `user_id` BINARY(16) NOT NULL,
                    `acl_role_id` BINARY(16) NOT NULL,
                    `provider_id` BINARY(16) NOT NULL,
                    `created_at` DATETIME(3) NOT NULL,
                    PRIMARY KEY (`user_id`, `acl_role_id`),
                    KEY `fk.sw6oidc_managed_acl_role.acl_role_id` (`acl_role_id`),
                    KEY `fk.sw6oidc_managed_acl_role.provider_id` (`provider_id`),
                    CONSTRAINT `fk.sw6oidc_managed_acl_role.acl_role_id` FOREIGN KEY (`acl_role_id`)
                        REFERENCES `acl_role` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
                    CONSTRAINT `fk.sw6oidc_managed_acl_role.provider_id` FOREIGN KEY (`provider_id`)
                        REFERENCES `sw6oidc_provider` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
                    CONSTRAINT `fk.sw6oidc_managed_acl_role.user_id` FOREIGN KEY (`user_id`)
                        REFERENCES `user` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                SQL,
        ];
    }
}
