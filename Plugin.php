<?php

namespace Opentech\LDAP;

use App;
use Event;
use Session;
use System\Classes\PluginBase;
use Backend\Controllers\Users;
use System\Classes\SettingsManager;
use October\Rain\Support\Facades\Flash;

class Plugin extends PluginBase
{
    public $elevated = true;

    public function registerSettings()
    {
        return [
            'settings' => [
                'label'       => 'LDAP Settings',
                'description' => 'Manage LDAP based settings.',
                'category'    => SettingsManager::CATEGORY_USERS,
                'icon'        => 'icon-cog',
                'class'       => Models\Settings::class,
                'keywords'    => 'security ldap users',
                'permissions' => ['opentech.ldap.access_settings'],
            ]
        ];
    }

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
                'readOnly' => true,
                'type'    => 'dropdown',
                'default' => 'cms',
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
