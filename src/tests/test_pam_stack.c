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

#include <stdbool.h>
#include <string.h>

#include "tests/test_common.h"
#include "common/errno_t.h"
#include "lib/pam/pam.h"

errno_t
textfile_read(const char *filepath,
              unsigned int limit_KiB,
              char **_content)
{
    const char *stack = NULL;
    char *content;

    if (strcmp(filepath, "test_pam_stack_find_module__match") == 0) {
        stack = "auth sufficient pam_sss.so forward_pass\n"
                "auth required pam_deny.so\n"
                "account required pam_unix.so\n"
                "password requisite pam_pwquality.so try_first_pass local_users_only\n"
                "session optional pam_keyinit.so revoke\n";
    }

    if (strcmp(filepath, "test_pam_stack_find_module__no_match") == 0) {
        stack = "auth sufficient pam_sss.so forward_pass\n"
                "auth required pam_deny.so\n"
                "account required pam_unix.so\n"
                "password requisite pam_pwquality.so try_first_pass local_users_only\n"
                "session optional pam_keyinit.so revoke\n";
    }

    assert_non_null(stack);
    content = strdup(stack);
    assert_non_null(content);

    *_content = content;

    return EOK;
}

void test_pam_stack_find_module__match(void **state)
{
    struct pam_stack *stack;
    struct pam_stack *line;
    errno_t ret;

    ret = pam_stack_parse(__FUNCTION__, &stack);
    assert_int_equal(ret, EOK);
    assert_non_null(stack);

    line = pam_stack_find_module(stack, "password", "pam_pwquality.so");

    assert_non_null(line);
    assert_string_equal(line->line, "password requisite pam_pwquality.so try_first_pass local_users_only");
    assert_false(line->silent);
    assert_string_equal(line->phase, "password");
    assert_string_equal(line->action, "requisite");
    assert_string_equal(line->module, "pam_pwquality.so");
    assert_string_equal(line->parameters, "try_first_pass local_users_only");

    pam_stack_free(stack);
}

void test_pam_stack_find_module__no_match(void **state)
{
    struct pam_stack *stack;
    struct pam_stack *line;
    errno_t ret;

    ret = pam_stack_parse(__FUNCTION__, &stack);
    assert_int_equal(ret, EOK);
    assert_non_null(stack);

    line = pam_stack_find_module(stack, "password", "pam_unix.so");
    assert_null(line);

    pam_stack_free(stack);
}

int main(int argc, const char *argv[])
{

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_pam_stack_find_module__match),
        cmocka_unit_test(test_pam_stack_find_module__no_match),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
