<?php

use Opentech\LDAP\Models\Settings;

return [
    'hosts'            => explode(',', Settings::get('adldap_hosts')),
    'port'             => Settings::get('adldap_port', 389),
    'base_dn'          => Settings::get('adldap_base_dn'),

    'username'         => Settings::get('adldap_username'),
    'password'         => Settings::get('adldap_password'),

    'schema'           => env('ADLDAP_SCHEMA', \Adldap\Schemas\ActiveDirectory::class),
    'account_prefix'   => env('ADLDAP_ACCOUNT_PREFIX', ''), // 'ACME-'
    'account_suffix'   => env('ADLDAP_ACCOUNT_SUFFIX', ''), // '@acme.org'
    'follow_referrals' => env('ADLDAP_FOLLOW_REFERRALS', true),
    'use_ssl'          => env('ADLDAP_USE_SSL', false),
    'use_tls'          => env('ADLDAP_USE_TLS', false),
    'version'          => env('ADLDAP_VERSION', 3),
    'timeout'          => env('ADLDAP_TIMEOUT', 5),
];
