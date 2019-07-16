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
 * This file contains service definitions for the jwt authentication plugin.
 *
 * @package   auth_jwt
 * @copyright 2019 Adam King
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

$services = array (
    'jwtapi' => array(
        'functions' => array(
            'auth_jwt_authenticate',
            'auth_jwt_validation',
            'auth_jwt_update'
        ),
        'restrictedusers' => 1,
        'enabled' => 1
    )
);

$functions = array(
    'auth_jwt_authenticate' => array(
        'classname' => 'auth_jwt_external',
        'methodname' => 'authenticate',
        'classpath' => 'auth/jwt/externallib.php',
        'description' => 'Provides a JSON web token with the required authentication data.',
        'type' => 'write',
        'ajax' => false
    ),
    'auth_jwt_validation' => array(
        'classname' => 'auth_jwt_external',
        'methodname' => 'validation',
        'classpath' => 'auth/jwt/externallib.php',
        'description' => 'Validates a token generated on the Moodle server.',
        'type' => 'write',
        'ajax' => false
    ),
    'auth_jwt_update' => array(
        'classname' => 'auth_jwt_external',
        'methodname' => 'update_user',
        'classpath' => 'auth/jwt/externallib.php',
        'description' => 'Updates user credentials and credentials via REST',
        'type' => 'write',
        'ajax' => false
    )
);