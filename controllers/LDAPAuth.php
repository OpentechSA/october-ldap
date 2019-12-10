<?php

namespace Opentech\LDAP\Controllers;

use Backend;
use Backend\Models\AccessLog;
use BackendAuth;
use October\Rain\Auth\AuthException;
use Opentech\LDAP\Services\LDAPAuthManager;
use Session;
use System\Classes\UpdateManager;
use ValidationException;
use Validator;

class LDAPAuth extends Backend\Classes\Controller
{

    protected $publicActions = ['signin'];
    /**
     * Displays the log in page.
     */
    public function signin()
    {
        try {
            return $this->authenticate();
        } catch (\Exception $ex) {
            Session::flash('message', $ex->getMessage());
            return Backend::redirect('backend/auth/signin');
        }
    }

    public function authenticate()
    {
        $rules = [
            'login'    => 'required|between:2,255',
            'password' => 'required|between:4,255'
        ];

        $validation = Validator::make(post(), $rules);
        if ($validation->fails()) {
            throw new ValidationException($validation);
        }

        $username = post('login');
        $password = post('password');
        $user = BackendAuth::findUserByLogin($username);
        if (empty($user)) {
            throw new AuthException(sprintf('User "%s" is not granted to access backend. Please contact your administrator', $username));
        }

        if ($user->opentech_ldap_user_type === 'ldap') {
            $manager = LDAPAuthManager::instance();
            $manager->authenticate([
                'login' => $username,
                'password' => $password
            ]);
            $user = $manager->authenticate([
                'login' => $username,
                'password' => $password
            ], true);
        } else {
            $user = BackendAuth::authenticate([
                'login' => $username,
                'password' => $password
            ], true);
        }

        UpdateManager::instance()->update();
        AccessLog::add($user);
        return Backend::redirectIntended('backend');
    }
}
