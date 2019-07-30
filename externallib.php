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
 * This file contains authentication api functions for the JWT authentication plugin.
 *
 * @package   auth_jwt
 * @copyright 2019 Adam King
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once('JWT.php');

use auth_jwt\JWT;

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir . "/externallib.php");
require_once($CFG->dirroot . '/user/lib.php');

class auth_jwt_external extends external_api
{
    public static function authenticate_parameters()
    {
        return new external_function_parameters(
            array(
                'idnumber' => new external_value(PARAM_INT, 'ID number of the user')
            )
        );
    }

    public static function authenticate_returns()
    {
        return new external_single_structure(
            array(
                'token' => new external_value(PARAM_TEXT, 'The JWT token for the user')
            )
        );
    }

    public static function authenticate($idnumber)
    {
        global $DB;

        $params = self::validate_parameters(self::authenticate_parameters(), array('idnumber' => $idnumber));
        $transaction = $DB->start_delegated_transaction();

        $user = get_complete_user_data('idnumber', $idnumber);

        if (!$user)
        {
            throw new Exception("The requested user could not be found.");
        }

        $token = JWT::encode([
            'sub' => $user->id
        ]);

        return ['token' => $token];
    }

    public static function validation_parameters()
    {
        return new external_function_parameters(
            array(
                'token' => new external_value(PARAM_TEXT, 'The encoded JWT provided to a user.'),
                'secret' => new external_value(PARAM_TEXT, 'The JWT secret')
            )
        );
    }

    public static function validation_returns()
    {
        return new external_single_structure(
            array(
                'valid' => new external_value(PARAM_BOOL, 'Whether or not the token is valid')
            )
        );
    }

    public static function validation($token, $secret)
    {
        global $CFG;

        $config = get_config('auth_jwt');

        if ($secret != $config->secret)
        {
            Throw new Exception("Incorrect JWT secret");
        }

        $payload = JWT::decode($token);
        if(!empty($payload))
        {
            return [
                'valid' => true
            ];
        }

        return [
            'valid' => false
        ];
    }

    public static function create_user_parameters()
    {
        return new external_function_parameters(
            array(
                'secret' => new external_value(PARAM_TEXT, 'The JWT secret'),
                'userdata' => new external_single_structure(
                    array(
                        'idnumber' => new external_value(PARAM_INT, 'The ID of the external user'),
                        'username' => new external_value(PARAM_TEXT, 'The new username of the external user'),
                        'email' => new external_value(PARAM_TEXT, 'The new email of the external user'),
                        'firstname' => new external_value(PARAM_TEXT, 'The first name of the user'),
                        'lastname' => new external_value(PARAM_TEXT, 'The last name of the user'),
                    )
                )
            )
        );
    }

    public static function create_user_returns()
    {
        return new external_single_structure(
            array(
                'user' => new external_value(PARAM_INT, 'The ID of the Moodle user')
            )
        );
    }

    public static function create_user($secret, $userdata)
    {
        global $CFG, $DB;

        $config = get_config('auth_jwt');

        if ($secret != $config->secret)
        {
            Throw new Exception("Incorrect JWT secret");
        }

        $user = new stdClass();

        foreach ($userdata as $property => $value)
        {
            $user->$property = $value;
        }

        $user->auth = 'jwt';
        $user->deleted = 0;
        $user->confirmed = 1;
        $user->mnethostid = 1;

        $auth = get_auth_plugin('jwt');
        $newUser = $auth->user_signup($user, false);

        if (!$newUser)
        {
            throw new Exception("User was unable to be created");
        }

        return $newUser->id;
    }

    public static function update_user_parameters()
    {
        return new external_function_parameters(
            array(
                'jwt' => new external_value(PARAM_TEXT, 'The JWT'),
                'secret' => new external_value(PARAM_TEXT, 'The JWT secret'),
                'userdata' => new external_single_structure(
                    array(
                        'idnumber' => new external_value(PARAM_INT, 'The ID of the external user'),
                        'username' => new external_value(PARAM_TEXT, 'The new username of the external user'),
                        'email' => new external_value(PARAM_TEXT, 'The new email of the external user'),
                        'firstname' => new external_value(PARAM_TEXT, 'The first name of the user'),
                        'lastname' => new external_value(PARAM_TEXT, 'The last name of the user'),
                    )
                )
            )
        );
    }

    public static function update_user_returns()
    {
        return new external_single_structure(
            array(
                'user' => new external_value(PARAM_INT, 'The ID of the Moodle user')
            )
        );
    }

    public static function update_user($jwt, $secret, $userdata)
    {
        global $CFG, $DB;

        $config = get_config('auth_jwt');

        if ($secret != $config->secret)
        {
            Throw new Exception("Incorrect JWT secret");
        }

        \error_log(json_encode($userdata));

        // Validate the JWT
        $payload = JWT::decode($jwt);
        if(!empty($payload))
        {
            $user = $DB->get_record('user', array(
                'idnumber' => $userdata['idnumber']
            ));

            // If the user doesn't exist
            if (!$user)
            {
                // Create the user with the properties provided
                $user = new stdClass();

                foreach ($userdata as $property => $value)
                {
                    $user->$property = $value;
                }

                $user->auth = 'jwt';
                $user->deleted = 0;
                $user->confirmed = 1;
                $user->mnethostid = 1;

                $auth = get_auth_plugin('jwt');
                $created = $auth->user_signup($user, false);
            }
            else
            {
                \error_log("updating user");
                // Update the user with the properties provided
                foreach ($userdata as $property => $value)
                {
                    $user->$property = $value;
                }

                user_update_user($user, false);
            }

            return [
                'user' => $user->id
            ];
        }

        return [
            'user' => -1
        ];
    }

    public static function user_exists_parameters()
    {
        return new external_function_parameters(
            array(
                'idnumber' => new external_value(PARAM_INT, 'ID number of the user')
            )
        );
    }

    public static function user_exists_returns()
    {
        return new external_single_structure(
            array(
                'exists' => new external_value(PARAM_BOOL, 'Whether or not the user exists')
            )
        );
    }

    public static function user_exists($idnumber)
    {
        global $DB;

        $idnumber = \intval($idnumber);

        $user = $DB->get_record('user', array('idnumber' => $idnumber));

        if (!$user)
        {
            return [
                'exists' => false
            ];
        }

        return [
            'exists' => true
        ];
    }
}