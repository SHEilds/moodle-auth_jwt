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
 * This file contains auth functions for the JWT authentication plugin.
 *
 * @package   auth_jwt
 * @copyright 2019 Adam King
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir . '/authlib.php');
require_once($CFG->libdir . '/adodb/adodb.inc.php');

class auth_plugin_jwt extends \auth_plugin_base
{
    private $database;

    public function __construct()
    {
        $this->authtype = 'jwt';
        $this->config = get_config('auth_jwt');
    }

    /**
     * Old syntax of class constructor. Deprecated in PHP7.
     *
     * @deprecated since Moodle 3.1
     */
    public function auth_plugin_jwt()
    {
        debugging('Use of class name as constructor is deprecated', DEBUG_DEVELOPER);
        self::__construct();
    }

    /**
     * Returns true if the username and password work or don't exist and false
     * if the user exists and the password is wrong.
     *
     * @param string $username The username 
     * @param string $password The password
     * @return bool Authentication success or failure.
     */
    public function user_login($username, $password)
    {
        if (isset($GLOBALS['valid_token']) && $GLOBALS['valid_token'])
        {
            // TODO: Set the valid_token in GLOBALS on verification.
            unset($GLOBALS['valid_token']);
            return true;
        }

        return false;
    }

    public function user_signup($user, $notify = true)
    {
        global $CFG, $DB, $PAGE, $OUTPUT;

        require_once($CFG->dirroot . '/user/profile/lib.php');

        if ($this->user_exists($user->idnumber))
        {
            print_error('auth_jwt_user_exists', 'auth_jwt');
        }

        // Save the user
        $user->id = $DB->insert_record('user', $user);
        profile_save_data($user);

        // Check the user was created
        return $DB->get_record('user', array('idnumber' => $user->idnumber));
    }

    public function user_update($oldUser, $newUser)
    {
        return null;
    }

    public function user_delete($oldUser)
    {
    }

    /**
     * Updates the user's password.
     *
     * called when the user password is updated.
     *
     * @param  object  $user        User table object
     * @param  string  $newpassword Plaintext password
     * @return boolean result
     *
     */
    public function user_update_password($user, $newpassword)
    {
        $user = get_complete_user_data('id', $user->id);
    }

    /**
     * Connect to external database.
     *
     * @return ADOConnection
     * @throws moodle_exception
     */
    function db_init()
    {
        if (!$this->is_configured())
        {
            throw new moodle_exception('auth_jwtcantconnect', 'auth_jwt');
        }

        // Connect to the external database (forcing new connection).
        $authdb = ADONewConnection($this->config->driver);
        if (!empty($this->config->debugauthdb))
        {
            $authdb->debug = true;
            ob_start(); //Start output buffer to allow later use of the page headers.
        }

        $host = $this->config->databasehost;
        $port = $this->config->databaseport;

        $authdb->Connect(
            "{$host}:{$port}",
            $this->config->databaseuser,
            $this->config->databaseuserpassword,
            $this->config->database,
            true
        );

        $authdb->SetFetchMode(ADODB_FETCH_ASSOC);

        return $authdb;
    }

    /**
     * Returns user attribute mappings between moodle and the external database.
     *
     * @return array
     */
    function db_attributes()
    {
        $moodleattributes = array();

        // If we have custom fields then merge them with user fields.
        $customfields = $this->get_custom_user_profile_fields();
        if (!empty($customfields) && !empty($this->userfields))
        {
            $userfields = array_merge($this->userfields, $customfields);
        }
        else
        {
            $userfields = $this->userfields;
        }

        foreach ($userfields as $field)
        {
            if (!empty($this->config->{"field_map_$field"}))
            {
                $moodleattributes[$field] = $this->config->{"field_map_$field"};
            }
        }

        $moodleattributes['username'] = $this->config->databaseuserfield;



        return $moodleattributes;
    }

    /**
     * Reads any other information for a user from external database,
     * then returns it in an array.
     *
     * @param int $idnumber
     * @return array
     */
    function get_userinfo($identifier, $idnumber = false)
    {
        global $CFG;

        //$extusername = core_text::convert($username, 'utf-8', $this->config->databaseencoding);

        $authdb = $this->db_init();

        // Array to map local fieldnames we want, to external fieldnames.
        $selectfields = $this->db_attributes();

        $result = array();
        // If at least one field is mapped from external db, get that mapped data.
        if ($selectfields)
        {
            $select = array();

            $fieldcount = 0;
            foreach ($selectfields as $localname => $externalname)
            {
                // Without aliasing, multiple occurrences of the same external
                // name can coalesce in only occurrence in the result.
                $select[] = "$externalname AS F" . $fieldcount;
                $fieldcount++;
            }

            $select = implode(', ', $select);
            if ($idnumber === true)
            {
                $sql = "SELECT $select
                        FROM {$this->config->databasetable}
                        WHERE {$this->config->field_map_idnumber} = {$identifier}";
            }
            else
            {
                $sql = "SELECT $select
                        FROM {$this->config->databasetable}
                        WHERE {$this->config->fielduser} = {$identifier}";
            }

            $rs = $authdb->Execute($sql);

            if ($rs)
            {
                if (!$rs->EOF)
                {
                    $fields = $rs->FetchRow();
                    // Convert the associative array to an array of its values so we don't have to worry about the case of its keys.
                    $fields = array_values($fields);

                    foreach (array_keys($selectfields) as $index => $localname)
                    {
                        $value = $fields[$index];
                        $result[$localname] = core_text::convert($value, $this->config->databaseencoding, 'utf-8');
                    }
                }

                $rs->Close();
            }
        }

        $authdb->Close();

        return $result;
    }

    /**
     * Reads user information from DB and return it in an object.
     *
     * @param string $idnumber user ID number
     * @return array
     */
    function get_userinfo_asobj($idnumber)
    {
        $user_array = truncate_userinfo($this->get_userinfo($idnumber, true));

        $user = new stdClass();
        foreach ($user_array as $key => $value)
        {
            $user->{$key} = $value;
        }

        return $user;
    }

    function get_userlist()
    {
        $result = array();

        $authdb = $this->db_init();

        $rs = $authdb->Execute("SELECT {$this->config->field_map_idnumber}, {$this->config->databaseuserfield}
                                  FROM {$this->config->databasetable}");

        if (!$rs)
        {
            print_error('auth_jwtcantconnect', 'auth_jwt');
        }
        else if (!$rs->EOF)
        {
            while ($rec = $rs->FetchRow())
            {
                $rec = array_change_key_case((array)$rec, CASE_LOWER);
                // Set the index as the user's idnumber, instead.
                $result[$rec[$this->config->field_map_idnumber]] = strtolower(trim($rec[$this->config->databaseuserfield]));
                // array_push($result, $rec[strtolower($this->config->databaseuserfield)]);
            }
        }

        $authdb->Close();

        return $result;
    }

    /**
     * Synchronizes user from external db to moodle user table.
     *
     * Sync should be done by using idnumber attribute, not username.
     * You need to pass firstsync parameter to function to fill in
     * idnumbers if they don't exists in moodle user table.
     *
     * Syncing users removes (disables) users that don't exists anymore in external db.
     * Creates new users and updates coursecreator status of users.
     *
     * This implementation is simpler but less scalable than the one found in the LDAP module.
     *
     * @param progress_trace $trace
     * @param bool $do_updates  Optional: set to true to force an update of existing accounts
     * @return int 0 means success, 1 means failure
     */
    function sync_users(progress_trace $trace, $do_updates = false)
    {
        global $CFG, $DB;

        require_once($CFG->dirroot . '/user/lib.php');

        // List external users.
        $userlist = $this->get_userlist();

        // Delete obsolete internal users.
        if (!empty($this->config->removeuser))
        {
            $suspendselect = "";
            if ($this->config->removeuser == get_string('auth_remove_suspend', 'auth'))
            {
                $suspendselect = "AND u.suspended = 0";
            }

            // Find obsolete users.
            if (count($userlist))
            {
                $removeusers = array();

                $params['authtype'] = $this->authtype;
                $sql = "SELECT u.id, u.username
                          FROM {user} u
                         WHERE u.auth=:authtype
                           AND u.deleted=0
                           AND u.mnethostid=:mnethostid
                           $suspendselect";
                $params['mnethostid'] = $CFG->mnet_localhost_id;
                $internalusersrs = $DB->get_recordset_sql($sql, $params);

                $usernamelist = array_flip($userlist);
                foreach ($internalusersrs as $internaluser)
                {
                    if (!array_key_exists($internaluser->username, $usernamelist))
                    {
                        $removeusers[] = $internaluser;
                    }
                }

                $internalusersrs->close();
            }
            else
            {
                $sql = "SELECT u.id, u.username
                          FROM {user} u
                         WHERE u.auth=:authtype AND u.deleted=0 AND u.mnethostid=:mnethostid $suspendselect";
                $params = array();
                $params['authtype'] = $this->authtype;
                $params['mnethostid'] = $CFG->mnet_localhost_id;

                $removeusers = $DB->get_records_sql($sql, $params);
            }

            if (!empty($removeusers))
            {
                $trace->output(get_string('auth_jwtuserstoremove', 'auth_jwt', count($removeusers)));

                foreach ($removeusers as $user)
                {
                    if ($this->config->removeuser == get_string('auth_remove_delete', 'auth'))
                    {
                        delete_user($user);
                        $trace->output(get_string('auth_jwtdeleteuser', 'auth_jwt', array('name' => $user->username, 'id' => $user->id)), 1);
                    }
                    else if ($this->config->removeuser == get_string('auth_remove_suspend', 'auth'))
                    {
                        $updateuser = new stdClass();
                        $updateuser->id   = $user->id;
                        $updateuser->suspended = 1;
                        user_update_user($updateuser, false);
                        $trace->output(get_string('auth_jwtsuspenduser', 'auth_jwt', array('name' => $user->username, 'id' => $user->id)), 1);
                    }
                }
            }

            unset($removeusers);
        }

        if (!count($userlist))
        {
            // Exit right here, nothing else to do.
            $trace->finished();
            return 0;
        }

        // Update existing accounts.
        if ($do_updates)
        {
            // Narrow down what fields we need to update.
            $all_keys = array_keys(get_object_vars($this->config));
            $updatekeys = array();

            foreach ($all_keys as $key)
            {
                if (preg_match('/^field_updatelocal_(.+)$/', $key, $match))
                {
                    if ($this->config->{$key} === 'onlogin')
                    {
                        array_push($updatekeys, $match[1]); // The actual key name.
                    }
                }
            }

            unset($all_keys);
            unset($key);

            // Only go ahead if we actually have fields to update locally.
            if (!empty($updatekeys))
            {
                $update_users = array();

                // All the drivers can cope with chunks of 10,000. See line 4491 of lib/dml/tests/dml_est.php
                $userlistchunks = array_chunk($userlist, 10000, true);
                foreach ($userlistchunks as $userlistchunk)
                {
                    list($in_sql, $params) = $DB->get_in_or_equal(array_keys($userlistchunk), SQL_PARAMS_NAMED, 'u', true);

                    $params['authtype'] = $this->authtype;
                    $params['mnethostid'] = $CFG->mnet_localhost_id;
                    $sql = "SELECT u.id, u.username, u.idnumber, u.suspended
                          FROM {user} u
                         WHERE u.auth = :authtype AND u.deleted = 0 AND u.mnethostid = :mnethostid AND u.idnumber {$in_sql}";

                    $update_users = $update_users + $DB->get_records_sql($sql, $params);
                }

                if ($update_users)
                {
                    $trace->output("User entries to update: " . count($update_users));
                    foreach ($update_users as $user)
                    {
                        if ($this->update_user_record($user->idnumber, $updatekeys, false, (bool) $user->suspended))
                        {
                            $trace->output(get_string('auth_jwtupdatinguser', 'auth_jwt', array('name' => $user->username, 'id' => $user->id)), 1);
                        }
                        else
                        {
                            $trace->output(get_string('auth_jwtupdatinguser', 'auth_jwt', array('name' => $user->username, 'id' => $user->id)) . " - " . get_string('skipped'), 1);
                        }
                    }

                    unset($update_users);
                }
            }
        }


        // Create missing accounts.
        // NOTE: this is very memory intensive and generally inefficient.
        $suspendselect = "";
        if ($this->config->removeuser == get_string('auth_remove_suspend', 'auth'))
        {
            $suspendselect = "AND u.suspended = 0";
        }
        $sql = "SELECT u.id, u.username
                  FROM {user} u
                 WHERE u.deleted='0' $suspendselect";

        $users = $DB->get_records_sql($sql);

        // Simplify down to usernames.
        $usernames = array();
        if (!empty($users))
        {
            foreach ($users as $user)
            {
                array_push($usernames, $user->username);
            }

            unset($users);
        }

        $add_users = array_diff($userlist, $usernames);
        unset($usernames);

        if (!empty($add_users))
        {
            $trace->output(get_string('auth_jwtuserstoadd', 'auth_jwt', count($add_users)));

            // Do not use transactions around this foreach, we want to skip problematic users, not revert everything.
            foreach ($add_users as $userIdNumber => $user)
            {
                $username = trim($user);

                if ($this->config->removeuser == get_string('auth_remove_suspend', 'auth'))
                {
                    $olduser = $DB->get_record(
                        'user',
                        array(
                            'idnumber' => $userIdNumber,
                            'deleted' => 0,
                            'suspended' => 1,
                            'auth' => $this->authtype
                        )
                    );

                    if ($olduser)
                    {
                        $updateuser = new stdClass();
                        $updateuser->id = $olduser->id;
                        $updateuser->suspended = 0;
                        user_update_user($updateuser);
                        $trace->output(get_string('auth_jwtreviveduser', 'auth_jwt', array(
                            'name' => $username,
                            'id' => $olduser->id
                        )), 1);

                        continue;
                    }
                }

                // Do not try to undelete users here, instead select suspending if you ever expect users will reappear.

                // Prep a few params.
                $user = $this->get_userinfo_asobj($userIdNumber);
                $user->username   = trim(strtolower($username));
                $user->idnumber   = $userIdNumber;
                $user->confirmed  = 1;
                $user->auth       = $this->authtype;
                $user->mnethostid = $CFG->mnet_localhost_id;

                if (empty($user->lang))
                {
                    $user->lang = $CFG->lang;
                }

                $duplicateIdnumberCollision = $DB->get_record('user', array('idnumber' => $user->idnumber));
                $alternateAuthCollision = $DB->get_record_select(
                    'user',
                    "idnumber = :idnumber AND auth <> :auth",
                    array(
                        'idnumber' => $user->idnumber,
                        'auth' => $this->authtype,
                    ),
                    'id,auth'
                );

                if ($duplicateIdnumberCollision)
                {
                    $trace->output(get_string('auth_jwtinseruserduplicateid', 'auth_jwt', array('username' => $user->username, 'idnumber' => $userIdNumber)), 1);
                    continue;
                }

                if ($alternateAuthCollision)
                {
                    $trace->output(get_string('auth_jwtinsertuserduplicate', 'auth_jwt', array('username' => $user->username, 'auth' => $collision->auth)), 1);
                    continue;
                }

                if (!$alternateAuthCollision && !$duplicateIdnumberCollision)
                {
                    try
                    {
                        // $trace->output("Collision detection: " . json_encode($collision));
                        // $trace->output("Attempting to create user: " . json_encode($user));
                        $id = user_create_user($user, false); // It is truly a new user.
                        $trace->output(get_string('auth_jwtinsertuser', 'auth_jwt', array('name' => $user->username, 'id' => $id)), 1);

                        // If relevant, tag for password generation.
                        if ($this->is_internal())
                        {
                            set_user_preference('auth_forcepasswordchange', 1, $id);
                            set_user_preference('create_password', 1, $id);
                        }

                        // Save custom profile fields here.
                        require_once($CFG->dirroot . '/user/profile/lib.php');
                        $user->id = $id;
                        profile_save_data($user);

                        // Make sure user context is present.
                        context_user::instance($id);
                    }
                    catch (moodle_exception $e)
                    {
                        $a = new stdClass();
                        $a->username = $user->username;
                        $a->message = $e->getMessage();

                        $trace->output(get_string('auth_jwtinsertusererrorverbose', 'auth_jwt', $a), 1);
                        continue;
                    }
                }
            }

            unset($add_users);
        }

        $trace->finished();

        return 0;
    }

    public function prevent_local_passwords()
    {
        return !$this->is_internal();
    }

    function user_exists($idnumber)
    {
        $authdb = $this->db_init();
        $result = false;

        $rs = $authdb->Execute("SELECT *
                                  FROM {$this->config->databasetable}
                                 WHERE {$this->config->field_map_idnumber} = " . $idnumber);

        if (!$rs)
        {
            print_error('auth_hashdbcantconnect', 'auth_hashdb');
        }
        else if (!$rs->EOF)
        {
            // User exists externally.
            $result = true;
        }

        $authdb->Close();
        return $result;
    }

    function ext_addslashes($text)
    {
        if (empty($this->config->sybasequoting))
        {
            $text = str_replace('\\', '\\\\', $text);
            $text = str_replace(array('\'', '"', "\0"), array('\\\'', '\\"', '\\0'), $text);
        }
        else
        {
            $text = str_replace("'", "''", $text);
        }

        return $text;
    }

    /**
     * Returns true if this authentication plugin is 'internal'.
     *
     * @return bool
     */
    public function is_internal()
    {
        return false;
    }

    /**
     * Returns true if this authentication plugin can change the user's
     * password.
     *
     * @return bool
     */
    public function can_change_password()
    {
        return false;
    }

    /**
     * Returns the URL for changing the user's pw, or empty if the default can
     * be used.
     *
     * @return moodle_url
     */
    public function change_password_url()
    {
        return null;
    }

    /**
     * Returns true if plugin allows resetting of internal password.
     *
     * @return bool
     */
    public function can_reset_password()
    {
        return false;
    }

    public function logoutpage_hook()
    {
        global $redirect;

        $GLOBALS['valid_token'] = false;

        $config = get_config('auth_jwt');
        $redirect = $config->logouturi;
    }

    /**
     * Returns true if plugin can be manually set.
     *
     * @return bool
     */
    public function can_be_manually_set()
    {
        return true;
    }

    public function can_signup()
    {
        return false;
    }

    public function is_configured()
    {

        $configured = !empty($this->config->databasehost) &&
            !empty($this->config->databaseuser) &&
            !empty($this->config->database) &&
            !empty($this->config->databasetable) &&
            !empty($this->config->databaseuserfield) &&
            !empty($this->config->driver);

        return $configured;
    }

    public function test_settings()
    {
        // Test the connections
    }
}
