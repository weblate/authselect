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
#include <stdbool.h>
#include <stdlib.h>
#include <regex.h>

#include "common/common.h"
#include "lib/pam/pam.h"
#include "lib/util/dlinklist.h"
#include "lib/util/util.h"
#include "lib/constants.h"

static void
pam_line_free(struct pam_stack **stack, struct pam_stack *line)
{
    if (line == NULL) {
        return;
    }

    if (stack != NULL) {
        DLIST_REMOVE(*stack, line);
    }

    free(line->line);
    free(line->phase);
    free(line->action);
    free(line->module);
    free(line->parameters);
    free(line);
}

static errno_t
pam_line_parse_substack(const char *input_line,
                        struct pam_stack **_line)
{
    struct pam_stack *line = NULL;
    regex_t regex;
    regmatch_t m[4];
    errno_t ret;
    int reret;

    reret = regcomp(&regex,
                    "^(auth|password|account|session)[ \t]+" /* m1: phase */
                    "(include|substack)[ \t]+" /* m2: action */
                    "(.*)$", /* m3: file */
                    REG_EXTENDED | REG_NEWLINE);
    if (reret != REG_NOERROR) {
        ERROR("Unable to compile regular expression: regex error %d", reret);
        return EFAULT;
    }

    reret = regexec(&regex, input_line, 4, m, 0);
    if (reret == REG_NOMATCH) {
        ERROR("No match found. Invalid line: %s", input_line);
        ret = EBADMSG;
        goto done;
    } else if (reret != REG_NOERROR) {
        ERROR("Unable to search string: regex error %d", reret);
        ret = EIO;
        goto done;
    }

    /* We have a match. */
    line = malloc_zero(struct pam_stack);
    if (line == NULL) {
        ret = ENOMEM;
        goto done;
    }

    line->silent = false;

    line->phase = strndup(input_line + m[1].rm_so, m[1].rm_eo - m[1].rm_so);
    if (line->phase == NULL) {
        ret = ENOMEM;
        goto done;
    }

    line->action = strndup(input_line + m[2].rm_so, m[2].rm_eo - m[2].rm_so);
    if (line->action == NULL) {
        ret = ENOMEM;
        goto done;
    }

    line->module = strndup(input_line + m[3].rm_so, m[3].rm_eo - m[3].rm_so);
    if (line->module == NULL) {
        ret = ENOMEM;
        goto done;
    }

    line->parameters = strdup("");
    if (line->parameters == NULL) {
        ret = ENOMEM;
        goto done;
    }

    line->line = format("%s %s %s", line->phase, line->action, line->module);
    if (line->line == NULL) {
        ret = ENOMEM;
        goto done;
    }

    *_line = line;

    ret = EOK;

done:
    if (ret != EOK) {
        pam_line_free(NULL, line);
    }

    regfree(&regex);
    return ret;
}

static errno_t
pam_line_parse_module(const char *input_line,
                      struct pam_stack **_line)
{
    struct pam_stack *line = NULL;
    regex_t regex;
    regmatch_t m[5];
    errno_t ret;
    int reret;

    reret = regcomp(&regex,
                    "^-?(auth|password|account|session)[ \t]+" /* m1: phase */
                    "(required|requisite|sufficient|optional|\\[.*\\])[ \t]+" /* m2: action */
                    "(.*\\.so)" /* m3: module */
                    "[ \t]*(.*)$", /* m4: parameters */
                    REG_EXTENDED | REG_NEWLINE);
    if (reret != REG_NOERROR) {
        ERROR("Unable to compile regular expression: regex error %d", reret);
        return EFAULT;
    }

    reret = regexec(&regex, input_line, 5, m, 0);
    if (reret == REG_NOMATCH) {
        ERROR("No match found. Invalid line: %s", input_line);
        ret = EBADMSG;
        goto done;
    } else if (reret != REG_NOERROR) {
        ERROR("Unable to search string: regex error %d", reret);
        ret = EIO;
        goto done;
    }

    /* We have a match. */
    line = malloc_zero(struct pam_stack);
    if (line == NULL) {
        ret = ENOMEM;
        goto done;
    }

    line->silent = input_line[0] == '-' ? true : false;

    line->phase = strndup(input_line + m[1].rm_so, m[1].rm_eo - m[1].rm_so);
    if (line->phase == NULL) {
        ret = ENOMEM;
        goto done;
    }

    line->action = strndup(input_line + m[2].rm_so, m[2].rm_eo - m[2].rm_so);
    if (line->action == NULL) {
        ret = ENOMEM;
        goto done;
    }

    line->module = strndup(input_line + m[3].rm_so, m[3].rm_eo - m[3].rm_so);
    if (line->module == NULL) {
        ret = ENOMEM;
        goto done;
    }

    line->parameters = strndup(input_line + m[4].rm_so, m[4].rm_eo - m[4].rm_so);
    if (line->parameters == NULL) {
        ret = ENOMEM;
        goto done;
    }

    line->line = format("%s%s %s %s%s%s", line->silent ? "-" : "",
                        line->phase, line->action, line->module,
                        line->parameters[0] != '\0' ? " " : "",
                        line->parameters);
    if (line->line == NULL) {
        ret = ENOMEM;
        goto done;
    }

    *_line = line;

    ret = EOK;

done:
    if (ret != EOK) {
        pam_line_free(NULL, line);
    }

    regfree(&regex);
    return ret;
}

static errno_t
pam_line_parse(const char *input_line,
               struct pam_stack **_line)
{
    errno_t ret;

    ret = pam_line_parse_module(input_line, _line);
    if (ret == EBADMSG) {
        ret = pam_line_parse_substack(input_line, _line);
    }

    return ret;
}

void
pam_stack_free(struct pam_stack *stack)
{
    struct pam_stack *line;
    struct pam_stack *tmp;

    if (stack == NULL) {
        return;
    }

    DLIST_FOR_EACH_SAFE(line, tmp, stack) {
        pam_line_free(&stack, line);
    }
}

static errno_t
pam_stack_parse_phase(char **antiloop,
                      const char *stackpath,
                      const char *phase,
                      struct pam_stack **_stack);

static errno_t
pam_stack_parse_substack(char **antiloop,
                         const char *parent,
                         const char *phase,
                         struct pam_stack **stack)
{
    const char *include_actions[] = {"include", "substack", NULL};
    struct pam_stack *substack;
    struct pam_stack *line;
    struct pam_stack *next;
    char *stackpath = NULL;
    char *dirpath;
    errno_t ret;

    DLIST_FOR_EACH_SAFE(line, next, *stack) {
        if (!string_in(line->action, include_actions)) {
            continue;
        }

        if (line->module[0] != '/') {
            dirpath = file_get_parent_directory(parent);
            if (dirpath == NULL) {
                return EINVAL;
            }

            /* Keep the same file name if parent does not contain directory. */
            if (dirpath && strcmp(dirpath, ".") == 0) {
                stackpath = strdup(line->module);
            } else {
                stackpath = format("%s/%s", dirpath, line->module);
            }

            free(dirpath);
        } else {
            stackpath = strdup(line->module);
        }

        if (stackpath == NULL) {
            return ENOMEM;
        }

        ret = pam_stack_parse_phase(antiloop, stackpath, phase, &substack);
        free(stackpath);
        if (ret != EOK) {
            return ret;
        }

        DLIST_ADD_LIST_AFTER(*stack, line, substack, struct pam_stack *);
        pam_line_free(stack, line);
    }

    return EOK;
}

static errno_t
pam_stack_parse_phase(char **antiloop,
                      const char *stackpath,
                      const char *phase,
                      struct pam_stack **_stack)
{
    struct pam_stack *stack = NULL;
    char **stacklines = NULL;
    struct pam_stack *line;
    char *stackcontent;
    errno_t ret;
    int i;

    if (string_array_has_value(antiloop, stackpath)) {
        return ELOOP;
    }

    antiloop = string_array_add_value(antiloop, stackpath, false);
    if (antiloop == NULL) {
        return ENOMEM;
    }

    ret = textfile_read(stackpath, AUTHSELECT_FILE_SIZE_LIMIT, &stackcontent);
    if (ret != EOK) {
        return ret;
    }

    stacklines = string_explode(stackcontent, '\n', STRING_EXPLODE_ALL);
    free(stackcontent);
    if (stacklines == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* First parse this file. */
    for (i = 0; stacklines[i] != NULL; i++) {
        ret = pam_line_parse(stacklines[i], &line);
        if (ret != EOK) {
            goto done;
        }

        if (strcmp(line->phase, phase) != 0) {
            pam_line_free(NULL, line);
            continue;
        }

        DLIST_ADD_END(stack, line, struct pam_stack *);
    }

    ret = pam_stack_parse_substack(antiloop, stackpath, phase, &stack);
    if (ret != EOK) {
        goto done;
    }

    *_stack = stack;

    ret = EOK;

done:
    if (ret != EOK) {
        pam_stack_free(stack);
    }

    string_array_free(stacklines);

    return ret;
}

errno_t
pam_stack_parse(const char *stackpath,
                struct pam_stack **_stack)
{
    const char *phases[] = {"account", "auth", "password", "session", NULL};
    struct pam_stack *stack = NULL;
    struct pam_stack *phase;
    char **antiloop;
    errno_t ret;
    int i;

    for (i = 0; phases[i] != NULL; i++) {
        antiloop = string_array_create(10);
        if (antiloop == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = pam_stack_parse_phase(antiloop, stackpath, phases[i], &phase);
        string_array_free(antiloop);
        if (ret != EOK) {
            goto done;
        }

        DLIST_CONCATENATE(stack, phase, struct pam_stack *);
    }

    *_stack = stack;

    ret = EOK;

done:
    if (ret != EOK) {
        pam_stack_free(stack);
    }

    return ret;
}
