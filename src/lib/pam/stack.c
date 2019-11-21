/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2018 Red Hat

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

#include "common/common.h"
#include "lib/pam/pam.h"
#include "lib/util/dlinklist.h"

struct pam_stack *
pam_stack_find_module(struct pam_stack *stack,
                      const char *phase,
                      const char *module)
{
    struct pam_stack *line;

    DLIST_FOR_EACH(line, stack) {
        if (strcmp(line->phase, phase) != 0) {
            continue;
        }

        if (strcmp(line->module, module) != 0) {
            continue;
        }

        return line;
    }

    return NULL;
}
