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
 * English localisation strings for the jwt authentication plugin.
 *
 * @package   auth_jwt
 * @copyright 2019 Adam King
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

$string['pluginname'] = 'jwt';
$string['plugingroup'] = 'jwt';

/**
 * JWT localisation
 */
$string['jwtissuer'] = 'Token Issuer';
$string['jwtissuer_desc'] = 'The issuer domain of the token.';
$string['jwtsecret'] = 'Token Secret Key';
$string['jwtsecret_desc'] = 'The secret key to encrypt JWT with.';
$string['jwtexpiry'] = 'Token Expiry';
$string['jwtexpiry_desc'] = 'Time until tokens expire, in seconds.';
$string['jwtlogoutpage'] = 'Log Out Page';
$string['jwtlogoutpage_desc'] = 'The page which the user will be redirected to upon logout.';

/**
 * Database localisation
 */
$string['jwtdatabaseheader'] = 'External Database Settings';
$string['jwtdatabasehost'] = 'External user database host';
$string['jwtdatabasehost_desc'] = 'The IP or domain of the database host server';
$string['jwtdatabaseport'] = 'External user database port';
$string['jwtdatabaseport_desc'] = 'The port of the database host server';
$string['jwtdatabaseuser'] = 'External database user';
$string['jwtdatabaseuser_desc'] = 'The external database user';
$string['jwtdatabaseuserpassword'] = 'External database user password';
$string['jwtdatabaseuserpassword_desc'] = 'The password for the database user';
$string['jwtdatabase'] = 'External user database name';
$string['jwtdatabase_desc'] = 'The database to use for external users';
$string['jwtdatabasetable'] = 'External user database table';
$string['jwtdatabasetable_desc'] = 'The database table to use for external users';
$string['jwtdatabaseuserfield'] = 'Database username field';
$string['jwtdatabaseuserfield_desc'] = 'The table field to use for username vaules';
$string['jwtsybasequoting'] = 'Use sybase quotes';
$string['jwtsybasequoting_desc'] = 'Sybase style single quote escaping - needed for Oracle, MS SQL and some other databases. Do not use for MySQL!';
$string['jwtextrafields'] = 'These fields are optional.  You can choose to pre-fill some Moodle user fields with information from the <b>external database fields</b> that you specify here. <p>If you leave these blank, then defaults will be used.</p><p>In either case, the user will be able to edit all of these fields after they log in.</p>';
$string['jwtdriver'] = 'External Database Driver';
$string['jwtdriver_desc'] = 'The external database type to determine the correct driver';
$string['jwtdatabaseencoding'] = 'Database Encoding';
$string['jwtdatabaseencoding_desc'] = 'The encoding of the external database';

/**
 * Sync localisation
 */
$string['jwtupdateusers'] = 'Update users';
$string['jwtupdateusers_desc'] = 'As well as inserting new users, update existing users';
$string['auth_jwtuserstoremove'] = 'User entries to remove: {$a}';
$string['auth_jwtdeleteuser'] = 'Deleted user {$a->name} id {$a->id}';
$string['auth_jwtsuspenduser'] = 'Suspended user {$a->name} id {$a->id}';
$string['auth_jwtupdatinguser'] = 'Updating user {$a->name} id {$a->id}';
$string['auth_jwtuserstoadd'] = 'User entries to add: {$a}';
$string['auth_jwtreviveduser'] = 'Revived user {$a->name} id {$a->id}';
$string['auth_jwtinsertuser'] = 'Inserted user {$a->name} id {$a->id}';
$string['auth_jwtsyncuserstask'] = 'Synchronise jwt users task';

/**
 * Error message localisation
 */
$string['userchangeemail'] = 'For authentication purposes, users are not allowed to alter their email address.';
$string['auth_jwtrevivedusererror'] = 'Error reviving user {$a}';
$string['auth_jwtdeleteusererror'] = 'Error deleting user {$a}';
$string['auth_jwtinsertusererror'] = 'Error inserting user {$a}';
$string['auth_jwtinsertuserduplicate'] = 'Error inserting user {$a->username} - user with this username was already created through \'{$a->auth}\' plugin.';
$string['auth_jwtcantconnect'] = 'Could not connect to the specified authentication database...';