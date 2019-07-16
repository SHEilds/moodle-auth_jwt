<?php
// This file is part of JWT authentication plugin for Moodle.
//
// JWT authentication plugin for Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// JWT authentication plugin for Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with jwt authentication plugin for Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * This file contains config functions for the JWT authentication plugin.
 *
 * @package   auth_jwt
 * @copyright 2019 Adam King
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

$yesno = array(
    get_string('no'),
    get_string('yes'),
);

if ($hassiteconfig)
{
    /**
     * JWT
     */
    $settings->add(new admin_setting_configtext(
        'auth_jwt/issuer',
        get_string('jwtissuer', 'auth_jwt'),
        get_string('jwtissuer_desc', 'auth_jwt'), '', PARAM_TEXT
    ));

    $settings->add(new admin_setting_configpasswordunmask (
        'auth_jwt/secret',
        get_string('jwtsecret', 'auth_jwt'),
        get_string('jwtsecret_desc', 'auth_jwt'), '', PARAM_TEXT
    ));

    $settings->add(new admin_setting_configduration(
        'auth_jwt/expiry',
        get_string('jwtexpiry', 'auth_jwt'),
        get_string('jwtexpiry_desc', 'auth_jwt'), 0, 1
    ));

    $settings->add(new admin_setting_configtext(
        'auth_jwt/logouturi',
        get_string('jwtlogoutpage', 'auth_jwt'),
        get_string('jwtlogoutpage_desc', 'auth_jwt'), '', PARAM_TEXT
    ));

    /**
     * External User Database
     */
    $settings->add(new admin_setting_heading('auth_jwt/databasesettings', get_string('jwtdatabaseheader', 'auth_jwt'), ''));

    $settings->add(new admin_setting_configtext(
        'auth_jwt/databasehost',
        get_string('jwtdatabasehost', 'auth_jwt'),
        get_string('jwtdatabasehost_desc', 'auth_jwt'), '', PARAM_TEXT
    ));

    $settings->add(new admin_setting_configtext(
        'auth_jwt/databaseport',
        get_string('jwtdatabaseport', 'auth_jwt'),
        get_string('jwtdatabaseport_desc', 'auth_jwt'), '3306', PARAM_INT
    ));

    $settings->add(new admin_setting_configtext(
        'auth_jwt/databaseuser',
        get_string('jwtdatabaseuser', 'auth_jwt'),
        get_string('jwtdatabaseuser_desc', 'auth_jwt'), '', PARAM_TEXT
    ));

    $settings->add(new admin_setting_configpasswordunmask(
        'auth_jwt/databaseuserpassword',
        get_string('jwtdatabaseuserpassword', 'auth_jwt'),
        get_string('jwtdatabaseuserpassword_desc', 'auth_jwt'), '', PARAM_TEXT
    ));

    $settings->add(new admin_setting_configtext(
        'auth_jwt/database',
        get_string('jwtdatabase', 'auth_jwt'),
        get_string('jwtdatabase_desc', 'auth_jwt'), '', PARAM_TEXT
    ));

    $settings->add(new admin_setting_configtext(
        'auth_jwt/databasetable',
        get_string('jwtdatabasetable', 'auth_jwt'),
        get_string('jwtdatabasetable_desc', 'auth_jwt'), '', PARAM_TEXT
    ));

    $settings->add(new admin_setting_configtext(
        'auth_jwt/databaseuserfield',
        get_string('jwtdatabaseuserfield', 'auth_jwt'),
        get_string('jwtdatabaseuserfield_desc', 'auth_jwt'), '', PARAM_TEXT
    ));

    $settings->add(new admin_setting_configselect(
        'auth_jwt/sybasequoting',
        get_string('jwtsybasequoting', 'auth_jwt'),
        get_string('jwtsybasequoting_desc', 'auth_jwt'), 0, $yesno
    ));

    $dboptions = array();
    $dbtypes = array(
        "access", "ado_access", "ado", "ado_mssql", "borland_ibase", "csv", "db2",
        "fbsql", "firebird", "ibase", "informix72", "informix", "mssql", "mssql_n", "mssqlnative",
        "mysql", "mysqli", "mysqlt", "oci805", "oci8", "oci8po", "odbc", "odbc_mssql", "odbc_oracle",
        "oracle", "pdo", "postgres64", "postgres7", "postgres", "proxy", "sqlanywhere", "sybase", "vfp"
    );
    foreach ($dbtypes as $dbtype)
    {
        $dboptions[$dbtype] = $dbtype;
    }

    $settings->add(new admin_setting_configselect(
        'auth_jwt/driver',
        get_string('jwtdriver', 'auth_jwt'),
        get_string('jwtdriver_desc', 'auth_jwt'), 'mysqli', $dboptions)
    );

    $settings->add(new admin_setting_configtext(
        'auth_jwt/databaseencoding',
        get_string('jwtdatabaseencoding', 'auth_jwt'),
        get_string('jwtdatabaseencoding_desc', 'auth_jwt'), 'utf-8', PARAM_RAW_TRIMMED)
    );

    /**
     * Sync options
     */
    $settings->add(new admin_setting_heading('auth_jwt/usersync', get_string('auth_sync_script', 'auth'), ''));

    $deleteopt = array();
    $deleteopt[AUTH_REMOVEUSER_KEEP] = get_string('auth_remove_keep', 'auth');
    $deleteopt[AUTH_REMOVEUSER_SUSPEND] = get_string('auth_remove_suspend', 'auth');
    $deleteopt[AUTH_REMOVEUSER_FULLDELETE] = get_string('auth_remove_delete', 'auth');

    $settings->add(new admin_setting_configselect(
        'auth_jwt/removeuser',
        get_string('auth_remove_user_key', 'auth'),
        get_string('auth_remove_user', 'auth'), AUTH_REMOVEUSER_KEEP, $deleteopt
    ));

    $settings->add(new admin_setting_configselect(
        'auth_jwt/updateusers',
        get_string('jwtupdateusers', 'auth_jwt'),
        get_string('jwtupdateusers_desc', 'auth_jwt'), 0, $yesno
    ));

    $authplugin = get_auth_plugin('jwt');
    display_auth_lock_options(
        $settings,
        $authplugin->authtype,
        $authplugin->userfields,
        get_string('jwtextrafields', 'auth_jwt'),
        true,
        true,
        $authplugin->get_custom_user_profile_fields()
    );
}