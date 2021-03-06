<?php

/**
 * This file contains authentication api functions for the JWT authentication plugin.
 *
 * @package   auth_jwt
 * @copyright 2019 Adam King
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once('../../config.php');
require_once('JWT.php');

use auth_jwt\JWT;

defined('MOODLE_INTERNAL') || die();

global $CFG, $USER, $SESSION, $err, $DB, $PAGE;

$token = required_param('token', PARAM_TEXT);
$userId = required_param('idnumber', PARAM_TEXT);
$hash = required_param('hash', PARAM_TEXT);

$PAGE->set_url('/auth/jwt/login.php');
$PAGE->set_context(context_system::instance());
$urltogo = $CFG->wwwroot;

$payload = JWT::decode($token);
$subject = get_complete_user_data('idnumber', $userId);

if ($subject->id === $payload->sub)
{
    $GLOBALS['valid_token'] = true;

    $user = authenticate_user_login($subject->username, $hash);

    if ($user === false)
    {
        error_log($hash);
    }

    $USER = complete_user_login($user);
    $USER->loggedin = true;
    $USER->site = $CFG->wwwroot;

    $USER->password = $hash;
    $DB->update_record('user', $USER);

    set_moodle_cookie($USER->username);

    redirect($urltogo);
}
else
{
    $GLOBALS['valid_token'] = false;
    throw new \Exception("Token is not valid for the given user.");
}
