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
        $config = get_config('auth_jwt');

        error_log(isset($GLOBALS['valid_token']));
        if (isset($GLOBALS['valid_token']))
        {
            error_log($GLOBALS['valid_token']);
        }

        // Attempt the JWT method.
        if (isset($GLOBALS['valid_token']) && $GLOBALS['valid_token'] == true)
        {
            unset($GLOBALS['valid_token']);
            return true;
        }

        // Attempt the manual credential method.
        else if ($config->allowmanuallogin)
        {
            if (isset($username) && isset($password))
            {
                global $DB;

                $viableUser = $DB->get_record('user', array(
                    'username' => $username
                ));

                if ($viableUser)
                {
                    if (substr($viableUser->password, 0, 4) == "$2y$")
                    {
                        // Perform blowfish password verification.
                        if (password_verify($password, $viableUser->password))
                        {
                            return true;
                        }
                    }
                    else
                    {
                        // Perform MD5 hash comparison.
                        $passwordHash = md5($password . $config->loginsalt);

                        if ($passwordHash == $viableUser->password)
                        {
                            // Upgrade the MD5 password to a blowfish
                            $viableUser->password = password_hash($password, PASSWORD_DEFAULT);
                            $DB->update_record('user', $viableUser);

                            return true;
                        }
                    }
                }
            }
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
        return true;
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
     * @param  string  $newpassword New password - Plaintext if internal (Not allowed in JWT)
     * @return boolean result
     *
     */
    public function user_update_password($user, $newpassword)
    {
        global $DB;

        $user->password = $newpassword;

        $DB->update_record('user', $user);
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
            throw new moodle_exception('auth_jwtnotconfigured', 'auth_jwt');
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
        $config = get_config('auth_jwt');

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
            if (!empty($config->{"field_map_$field"}))
            {
                $moodleattributes[$field] = $config->{"field_map_$field"};
            }
        }

        $moodleattributes['username'] = $config->databaseuserfield;

        // If a password field has been set, include it.
        if (!empty($config->databasepasswordfield))
        {
            $moodleattributes['password'] = $config->databasepasswordfield;
        }

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
                        WHERE {$this->config->databaseuserfield} = {$identifier}";
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
    function get_userinfo_asobj($idnumber): stdClass
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
                // Set the index as the user's idnumber, instead.
                $rec = array_change_key_case((array)$rec, CASE_LOWER);
                $result[$rec[$this->config->field_map_idnumber]] = strtolower(trim($rec[$this->config->databaseuserfield]));
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
        // [idnumber => username]
        // username: trim/tolower
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
                         WHERE u.auth = :authtype AND u.deleted = 0 AND u.idnumber {$in_sql}";

                    $update_users = $update_users + $DB->get_records_sql($sql, $params);
                }

                if ($update_users)
                {
                    $trace->output("User entries to update: " . count($update_users));
                    foreach ($update_users as $user)
                    {
                        if ($this->update_user_record($user->idnumber, $updatekeys, false, (bool) $user->suspended))
                        {
                            $trace->output(
                                get_string(
                                    'auth_jwtupdatinguser',
                                    'auth_jwt',
                                    ['name' => $user->username, 'id' => $user->id]
                                ),
                                1
                            );
                        }
                        else
                        {
                            // $trace->output(
                            //     get_string(
                            //         'auth_jwtupdatinguser',
                            //         'auth_jwt',
                            //         ['name' => $user->username, 'id' => $user->id]
                            //     ) . " - " . get_string('skipped'),
                            //     1
                            // );
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

                $existingUserByIdnumber = $DB->get_record('user', array('idnumber' => $user->idnumber));
                $existingUserByAuthType = $DB->get_record_select(
                    'user',
                    "idnumber = :idnumber AND auth <> :auth",
                    array(
                        'idnumber' => $user->idnumber,
                        'auth' => $this->authtype,
                    ),
                    'id,auth'
                );

                if ($existingUserByIdnumber)
                {
                    // Use external as the source of thruth and update the user.
                    $authdb = $this->db_init();

                    $oldemail = $existingUserByIdnumber->email;
                    $oldusername = $existingUserByIdnumber->username;

                    $rs = $authdb->Execute(
                        "SELECT {$this->config->databaseuserfield},
                                {$this->config->databaseemailfield}
                        FROM {$this->config->databasetable}
                        WHERE {$this->config->field_map_idnumber} = {$user->idnumber}"
                    );

                    if (!$rs)
                    {
                        print_error('auth_jwtcantconnect', 'auth_jwt');
                    }
                    else if (!$rs->EOF)
                    {
                        while ($rec = $rs->FetchRow())
                        {
                            $rec = array_change_key_case((array)$rec, CASE_LOWER);

                            $existingUserByIdnumber->username = strtolower(trim($rec[$this->config->databaseuserfield]));
                            $existingUserByIdnumber->email = strtolower(trim($rec[$this->config->databaseemailfield]));
                        }
                    }

                    $authdb->Close();
                    $trace->output("Found idnumber collision ({$existingUserByIdnumber->idnumber}): rectifying with external source. ({$oldemail} <--> {$existingUserByIdnumber->email}), ({$oldusername} <--> {$existingUserByIdnumber->username})");
                    $DB->update_record('user', $existingUserByIdnumber);

                    continue;
                }

                if ($existingUserByAuthType)
                {
                    $trace->output(get_string('auth_jwtinsertuserduplicate', 'auth_jwt', array('username' => $user->username, 'auth' => $collision->auth)), 1);
                    continue;
                }

                if (!$existingUserByAuthType && !$existingUserByIdnumber)
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

    /**
     * Update a local user record from an external source.
     * This is a lighter version of the one in moodlelib -- won't do
     * expensive ops such as enrolment.
     *
     * @param string $idnumber idnumber
     * @param array $updatekeys fields to update, false updates all fields.
     * @param bool $triggerevent set false if user_updated event should not be triggered.
     *             This will not affect user_password_updated event triggering.
     * @param bool $suspenduser Should the user be suspended?
     * @return stdClass|bool updated user record or false if there is no new info to update.
     */
    protected function update_user_record($idnumber, $updatekeys = false, $triggerevent = false, $suspenduser = false)
    {
        global $CFG, $DB;

        require_once($CFG->dirroot . '/user/profile/lib.php');

        // Get the current user record.
        $user = $DB->get_record('user', array('idnumber' => $idnumber));
        if (empty($user))
        { // Trouble.
            error_log($this->errorlogtag . get_string('auth_usernotexist', 'auth', $user->username));
            print_error('auth_usernotexist', 'auth', '', $user->username);
            die;
        }

        // Protect the userid from being overwritten.
        $userid = $user->id;

        $needsupdate = false;

        if ($newinfo = $this->get_userinfo($idnumber, true))
        {
            $newinfo = truncate_userinfo($newinfo);

            if (empty($updatekeys))
            { // All keys? this does not support removing values.
                $updatekeys = array_keys($newinfo);
            }

            if (!empty($updatekeys))
            {
                $newuser = new stdClass();
                $newuser->id = $userid;
                // The cast to int is a workaround for MDL-53959.
                $newuser->suspended = (int) $suspenduser;
                // Load all custom fields.
                $profilefields = (array) profile_user_record($user->id, false);
                $newprofilefields = [];

                foreach ($updatekeys as $key)
                {
                    if (isset($newinfo[$key]))
                    {
                        $value = $newinfo[$key];
                    }
                    else
                    {
                        $value = '';
                    }

                    if (!empty($this->config->{'field_updatelocal_' . $key}))
                    {
                        if (preg_match('/^profile_field_(.*)$/', $key, $match))
                        {
                            // Custom field.
                            $field = $match[1];
                            $currentvalue = isset($profilefields[$field]) ? $profilefields[$field] : null;
                            $newprofilefields[$field] = $value;
                        }
                        else
                        {
                            // Standard field.
                            $currentvalue = isset($user->$key) ? $user->$key : null;
                            $newuser->$key = $value;
                        }

                        // Only update if it's changed.
                        if ($currentvalue !== $value)
                        {
                            $needsupdate = true;
                        }
                    }
                }
            }

            if ($this->config->allowmanuallogin && isset($newinfo['password']))
            {
                if (!empty($newinfo['password']))
                {
                    $newuser->password = $newinfo['password'];
                    $needsupdate = true;
                }
            }

            if ($needsupdate)
            {
                user_update_user($newuser, true, $triggerevent);
                profile_save_custom_fields($newuser->id, $newprofilefields);
                return $DB->get_record('user', array('id' => $userid, 'deleted' => 0));
            }
        }

        return false;
    }

    public function prevent_local_passwords()
    {
        // return !$this->is_internal();
        return false;
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
        return true;
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
