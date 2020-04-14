<?php return [
    'hosts'            => explode(',', env('ADLDAP_HOSTS', 'corp-dc1.corp.acme.org,corp-dc2.corp.acme.org')),
    'base_dn'          => env('ADLDAP_BASE_DN', 'dc=corp,dc=acme,dc=org'),

    'username'         => env('ADLDAP_USERNAME'),
    'password'         => env('ADLDAP_PASSWORD'),

    'schema'           => env('ADLDAP_SCHEMA', \Adldap\Schemas\ActiveDirectory::class),
    'account_prefix'   => env('ADLDAP_ACCOUNT_PREFIX', ''), // 'ACME-'
    'account_suffix'   => env('ADLDAP_ACCOUNT_SUFFIX', ''), // '@acme.org'
    'port'             => env('ADLDAP_PORT', 389),
    'follow_referrals' => env('ADLDAP_FOLLOW_REFERRALS', false),
    'use_ssl'          => env('ADLDAP_USE_SSL', false),
    'use_tls'          => env('ADLDAP_USE_TLS', false),
    'version'          => env('ADLDAP_VERSION', 3),
    'timeout'          => env('ADLDAP_TIMEOUT', 5),
];
