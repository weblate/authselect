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

#ifndef _PAM_H_
#define _PAM_H_

#include <stdbool.h>

#include "common/errno_t.h"

struct pam_stack {
    /**
     * Whole PAM line.
     */
    char *line;

    /**
     * PAM phase. One of auth, password, account, session.
     */
    char *phase;

    /**
     * PAM action. One of sufficient, requisite, required, optional
     * or custom specification in brackets (e.g. [ignore=ok]).
     */
    char *action;

    /**
     * PAM module name, including '.so' suffix. E.g. pam_unix.so.
     */
    char *module;

    /**
     * Module's parameters.
     */
    char *parameters;

    /**
     * True if missing module is ignored, i.e. when '-' is on the beginning
     * of line.
     */
    bool silent;

    struct pam_stack *prev;
    struct pam_stack *next;
};

/**
 * Free PAM stack.
 */
void
pam_stack_free(struct pam_stack *stack);

/**
 * Read file @stackpath and parse it into @pam_stack list.
 *
 * @param stackpath Path to the PAM stack file.
 * @param _stack    Linked list of PAM stack lines.
 *
 * @return EOK on success, other errno code on error.
 */
errno_t
pam_stack_parse(const char *stackpath,
                struct pam_stack **_stack);

/**
 * File PAM stack line that matches @phase and @module.
 *
 * @param stack  PAM stack obtained from @pam_stack_parse.
 * @param phase  PAM phase to look for.
 * @param module PAM module to look for.
 *
 * @return Found PAM line or NULL if no match was found.
 */
struct pam_stack *
pam_stack_find_module(struct pam_stack *stack,
                      const char *phase,
                      const char *module);

#endif /* _PAM_H_ */
