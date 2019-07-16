<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

namespace auth_jwt\task;

defined('MOODLE_INTERNAL') || die();

class sync_users extends \core\task\scheduled_task
{
    public function get_name()
    {
        return get_string('auth_jwtsyncuserstask', 'auth_jwt');
    }

    public function execute()
    {
        if (!is_enabled_auth('jwt'))
        {
            mtrace('auth_jwt plugin is disabled, synchronisation stopped', 2);
            return;
        }

        $dbauth = get_auth_plugin('jwt');
        $config = get_config('auth_jwt');
        $trace = new \text_progress_trace();
        $update = !empty($config->updateusers);
        $dbauth->sync_users($trace, $update);
    }
}
