<?php

namespace Opentech\LDAP\Models;

use Model;

class Settings extends Model
{
    public $implement = ['System.Behaviors.SettingsModel'];

    // A unique code
    public $settingsCode = 'opentech_ldap_settings';

    // Reference to field configuration
    public $settingsFields = 'fields.yaml';

    public function getRoleIdOptions()
    {
        return \Backend\Models\UserRole::pluck('name', 'id');
    }

    /**
     * Protects the password from being reset to null.
     */
    public function setValueAttribute($value)
    {
        $json = json_decode($value);
        if ($this->exists && empty($json->adldap_password)) {
            $json->adldap_password = $this->value['adldap_password'];
            $this->attributes['value'] = json_encode($json);
        } else {
            $this->attributes['value'] = $value;
        }
    }
}
