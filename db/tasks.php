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


defined('MOODLE_INTERNAL') || die();

$tasks = array(
    array(
        'classname' => '\auth_jwt\task\sync_users',
        'blocking' => 0,
        'minute' => 'R',
        'hour' => 'R',
        'day' => '*',
        'month' => '*',
        'dayofweek' => '*',
        'disabled' => 1
    )
);
