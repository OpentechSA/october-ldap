<?php

namespace Opentech\LDAP\Services;

use Backend\Classes\AuthManager;
use Adldap\Adldap as AdldapAdldap;
use October\Rain\Auth\AuthException;
use Opentech\LDAP\Models\Settings;

class LDAPAuthManager extends AuthManager
{
    protected static $instance;
    public $adldap;

    protected function init()
    {
        parent::init();
        $config = include plugins_path('opentech/ldap/config.php');
        $this->adldap = new AdldapAdldap(['default' => $config]);
    }

    public function authenticate(array $credentials, $remember = true)
    {
        /*
         * Default to the login name field or fallback to a hard-coded 'login' value
         */
        $loginName = $this->createUserModel()->getLoginName();
        $loginCredentialKey = (isset($credentials[$loginName])) ? $loginName : 'login';

        if (empty($credentials[$loginCredentialKey])) {
            throw new AuthException(sprintf('The "%s" attribute is required.', $loginCredentialKey));
        }

        if (empty($credentials['password'])) {
            throw new AuthException('The password attribute is required.');
        }
        /*
         * If the fallback 'login' was provided and did not match the necessary
         * login name, swap it over
         */
        if ($loginCredentialKey !== $loginName) {
            $credentials[$loginName] = $credentials[$loginCredentialKey];
            unset($credentials[$loginCredentialKey]);
        }

        /*
         * If throttling is enabled, check they are not locked out first and foremost.
         */
        if ($this->useThrottle) {
            try {
                $throttle = $this->findThrottleByLogin($credentials[$loginName], $this->ipAddress);
            } catch (AuthException $e) {
                $throttle = null;
            }

            if ($throttle) {
                $throttle->check();
            }
        }

        /*
         * Look up the user by authentication credentials.
         */
        try {
            $username = $credentials[$loginName];
            $password = $credentials['password'];

            $user = $this->authenticateWithAD($username, $password);
        } catch (AuthException $ex) {
            if ($this->useThrottle && $throttle) {
                $throttle->addLoginAttempt();
            }

            throw $ex;
        }

        if ($this->useThrottle && $throttle) {
            $throttle->clearLoginAttempts();
        }

        $user->clearResetPassword();
        $this->login($user, $remember);

        return $this->user;
    }

    protected function authenticateWithAD($username, $password)
    {
        try {
            $provider = $this->adldap->getDefaultProvider()->connect();

            if ($provider->auth()->attempt($username, $password)) {
                $adUser = $provider->search()->find($username);
                $user = $this->findUserByLogin($username);

                if (!$user) {
                    $user = self::register([
                        'login' => $username,
                        'password' => $password,
                        'password_confirmation' => $password,
                        'email' => $username . '@regional.com.py',
                        'opentech_ldap_user_type' => 'ldap',
                    ], true);
                }

                $user->role_id = $this->getUserRole($adUser->getAttribute('memberof')[0]);
                $user->save();

                return $user;
            }
            throw new \Exception('Invalid credentials', 1);
        } catch (\Exception $ex) {
            throw new AuthException($ex->getMessage());
        }
    }

    protected function getUserRole($memberOf)
    {
        $memberOf = collect(explode(',', $memberOf));
        $rules = Settings::get('role_rules', []);

        foreach ($rules as $rule) {
            if ($memberOf->search($rule['memberof'])) {
                return $rule['role_id'];
            }
        }
    }
}
