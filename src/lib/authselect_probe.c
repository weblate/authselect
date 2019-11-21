/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2017 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "authselect.h"
#include "common/common.h"
#include "lib/constants.h"
#include "lib/pam/pam.h"

_PUBLIC_ int
authselect_probe_enabled(enum authselect_probe probe, bool *_enabled)
{
    struct pam_stack *stack;
    struct pam_stack *line;
    const char *str;
    bool enabled;
    errno_t ret;

    ret = pam_stack_parse(AUTHSELECT_PAM_DIR "/" FILE_SYSTEM, &stack);
    if (ret != EOK) {
        return ret;
    }

    switch (probe) {
    case AUTHSELECT_PROBE_PAM_UNIX_NULLOK:
        line = pam_stack_find_module(stack, "auth", "pam_unix.so");
        if (line == NULL) {
            ret = ENOENT;
            goto done;
        }

        str = strstr(line->parameters, "nullok");
        enabled = str == NULL ? false : true;
        break;
    default:
        ERROR("Unknown probe: %d", probe);
        ret = EINVAL;
        goto done;
    }

    *_enabled = enabled;

    ret = EOK;

done:
    pam_stack_free(stack);

    return ret;
}
