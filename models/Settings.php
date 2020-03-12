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
}
