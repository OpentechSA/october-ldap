<?php

namespace Opentech\LDAP;

use App;
use Event;
use Session;
use System\Classes\PluginBase;
use Backend\Controllers\Users;
use October\Rain\Support\Facades\Flash;

class Plugin extends PluginBase
{
    public $elevated = true;

    public function boot()
    {
        Event::listen('backend.auth.extendSigninView', function ($controller) {
            $this->hookSigninForm($controller);
        });

        Event::listen('backend.form.extendFields', function ($widget) {
            $this->addFieldsToUserForm($widget);
        });

        Event::listen('backend.list.extendColumns', function ($widget) {
            $this->addFieldsToUserList($widget);
        });
    }


    protected function hookSigninForm($controller)
    {
        $controller->addJs('/plugins/opentech/ldap/assets/js/override-auth.js');
        $message = Session::get('message');
        if (!empty($message)) {
            Flash::error($message);
        }
    }

    protected function addFieldsToUserForm($widget)
    {
        if (!$widget->getController() instanceof Users) {
            return;
        }

        $widget->addFields([
            'opentech_ldap_user_type' => [
                'label'   => 'User type',
                'comment' => '(LDAP user if you want to connect with LDAP, CMS user if you want the user is managed inside the CMS)',
                'type'    => 'dropdown',
                'options' => [
                    'ldap' => 'LDAP user',
                    'cms' => 'CMS user',
                ]
            ]
        ]);
    }

    protected function addFieldsToUserList($widget)
    {
        if (!$widget->getController() instanceof Users) {
            return;
        }

        $widget->addColumns([
            'opentech_ldap_user_type' => [
                'label' => 'User type'
            ]
        ]);
    }
}
