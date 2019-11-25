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

    if (strcmp(filepath, "test_pam_stack_parse__single_line") == 0) {
        stack = "auth sufficient pam_sss.so forward_pass";
    }

    if (strcmp(filepath, "test_pam_stack_parse__silent") == 0) {
        stack = "-auth sufficient pam_sss.so forward_pass";
    }

    if (strcmp(filepath, "test_pam_stack_parse__no_params") == 0) {
        stack = "auth sufficient pam_sss.so";
    }

    if (strcmp(filepath, "test_pam_stack_parse__two_lines") == 0) {
        stack = "auth sufficient pam_sss.so forward_pass\n"
                "auth required pam_deny.so\n";
    }

    if (strcmp(filepath, "test_pam_stack_parse__brackets") == 0) {
        stack = "auth [default=1 ignore=ignore success=ok] pam_succeed_if.so uid >= 1000 quiet";
    }

    if (strcmp(filepath, "test_pam_stack_parse__comments") == 0) {
        stack = "# comment first line\n"
                "auth sufficient pam_sss.so forward_pass\n"
                "# auth required pam_deny.so\n";
    }

    if (strcmp(filepath, "test_pam_stack_parse__spaces") == 0) {
        stack = " auth   sufficient    pam_sss.so \tforward_pass ";
    }

    if (strcmp(filepath, "test_pam_stack_parse__phases") == 0) {
        stack = "account required pam_unix.so\n"
                "auth sufficient pam_sss.so forward_pass\n"
                "password requisite pam_pwquality.so try_first_pass local_users_only\n"
                "session optional pam_keyinit.so revoke\n";
    }

    if (strcmp(filepath, "test_pam_stack_parse__invalid_phase") == 0) {
        stack = "authentication sufficient pam_sss.so forward_pass";
    }

    if (strcmp(filepath, "test_pam_stack_parse__invalid_action") == 0) {
        stack = "auth bad pam_sss.so forward_pass";
    }

    if (strcmp(filepath, "test_pam_stack_parse__invalid_file") == 0) {
        return EACCES;
    }

    if (strcmp(filepath, "test_pam_stack_parse__include_single_line") == 0) {
        stack = "account include test_pam_stack_parse__phases\n";
    }

    if (strcmp(filepath, "test_pam_stack_parse__include_phases") == 0) {
        stack = "account include test_pam_stack_parse__phases\n"
                "auth include test_pam_stack_parse__phases\n"
                "password include test_pam_stack_parse__phases\n"
                "session include test_pam_stack_parse__phases\n";
    }

    if (strcmp(filepath, "test_pam_stack_parse__include_mixed") == 0) {
        stack = "account required pam_unix.so\n"
                "auth sufficient pam_pre.so\n"
                "auth include test_pam_stack_parse__phases\n"
                "auth sufficient pam_post.so\n"
                "password include test_pam_stack_parse__phases\n"
                "session include test_pam_stack_parse__phases\n";
    }

    if (strcmp(filepath, "test_pam_stack_parse__substack_single_line") == 0) {
        stack = "account substack test_pam_stack_parse__phases\n";
    }

    if (strcmp(filepath, "test_pam_stack_parse__substack_phases") == 0) {
        stack = "account substack test_pam_stack_parse__phases\n"
                "auth substack test_pam_stack_parse__phases\n"
                "password substack test_pam_stack_parse__phases\n"
                "session substack test_pam_stack_parse__phases\n";
    }

    if (strcmp(filepath, "test_pam_stack_parse__substack_mixed") == 0) {
        stack = "account required pam_unix.so\n"
                "auth sufficient pam_pre.so\n"
                "auth substack test_pam_stack_parse__phases\n"
                "auth sufficient pam_post.so\n"
                "password substack test_pam_stack_parse__phases\n"
                "session substack test_pam_stack_parse__phases\n";
    }

    if (strcmp(filepath, "test_pam_stack_parse__include_substack") == 0) {
        stack = "account include test_pam_stack_parse__phases\n"
                "auth substack test_pam_stack_parse__phases\n"
                "password include test_pam_stack_parse__phases\n"
                "session substack test_pam_stack_parse__phases\n";
    }

    if (strcmp(filepath, "test_pam_stack_parse__loop") == 0) {
        stack = "account include test_pam_stack_parse__loop_1\n";
    }

    if (strcmp(filepath, "test_pam_stack_parse__loop_1") == 0) {
        stack = "account substack test_pam_stack_parse__loop_2\n";
    }

    if (strcmp(filepath, "test_pam_stack_parse__loop_2") == 0) {
        stack = "account include test_pam_stack_parse__loop\n";
    }

    if (strcmp(filepath, "/etc/pam.d/system-auth") == 0) {
        stack = "account include system-auth-include\n"
                "auth substack /etc/other-pam.d/substack\n";
    }

    if (strcmp(filepath, "/etc/pam.d/system-auth-include") == 0) {
        stack = "account required pam_unix.so\n";
    }

    if (strcmp(filepath, "/etc/other-pam.d/substack") == 0) {
        stack = "auth required pam_sss.so\n";
    }

    assert_non_null(stack);
    content = strdup(stack);
    assert_non_null(content);

    *_content = content;

    return EOK;
}

void assert_pam_line(struct pam_stack *stack,
                     const char *line,
                     bool silent,
                     const char *phase,
                     const char *action,
                     const char *module,
                     const char *parameters)
{
    assert_non_null(stack);
    assert_string_equal(stack->line, line);
    assert_int_equal(stack->silent, silent);
    assert_string_equal(stack->phase, phase);
    assert_string_equal(stack->action, action);
    assert_string_equal(stack->module, module);
    assert_string_equal(stack->parameters, parameters);
}

void test_pam_stack_parse__single_line(void **state)
{
    struct pam_stack *stack;
    errno_t ret;

    ret = pam_stack_parse(__FUNCTION__, &stack);
    assert_int_equal(ret, EOK);

    assert_pam_line(stack, "auth sufficient pam_sss.so forward_pass", false,
                    "auth", "sufficient", "pam_sss.so", "forward_pass");
    assert_null(stack->prev);
    assert_null(stack->next);

    pam_stack_free(stack);
}

void test_pam_stack_parse__silent(void **state)
{
    struct pam_stack *stack;
    errno_t ret;

    ret = pam_stack_parse(__FUNCTION__, &stack);
    assert_int_equal(ret, EOK);

    assert_pam_line(stack, "-auth sufficient pam_sss.so forward_pass", true,
                    "auth", "sufficient", "pam_sss.so", "forward_pass");
    assert_null(stack->prev);
    assert_null(stack->next);

    pam_stack_free(stack);
}

void test_pam_stack_parse__no_params(void **state)
{
    struct pam_stack *stack;
    errno_t ret;

    ret = pam_stack_parse(__FUNCTION__, &stack);
    assert_int_equal(ret, EOK);

    assert_pam_line(stack, "auth sufficient pam_sss.so", false,
                    "auth", "sufficient", "pam_sss.so", "");
    assert_null(stack->prev);
    assert_null(stack->next);

    pam_stack_free(stack);
}

void test_pam_stack_parse__two_lines(void **state)
{
    struct pam_stack *stack;
    struct pam_stack *line;
    errno_t ret;

    ret = pam_stack_parse(__FUNCTION__, &stack);
    assert_int_equal(ret, EOK);

    line = stack;
    assert_pam_line(line, "auth sufficient pam_sss.so forward_pass", false,
                    "auth", "sufficient", "pam_sss.so", "forward_pass");
    assert_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "auth required pam_deny.so", false,
                    "auth", "required", "pam_deny.so", "");
    assert_non_null(line->prev);
    assert_null(line->next);

    pam_stack_free(stack);
}

void test_pam_stack_parse__brackets(void **state)
{
    struct pam_stack *stack;
    errno_t ret;

    ret = pam_stack_parse(__FUNCTION__, &stack);
    assert_int_equal(ret, EOK);

    assert_pam_line(stack, "auth [default=1 ignore=ignore success=ok] pam_succeed_if.so uid >= 1000 quiet", false,
                    "auth", "[default=1 ignore=ignore success=ok]", "pam_succeed_if.so", "uid >= 1000 quiet");
    assert_null(stack->prev);
    assert_null(stack->next);

    pam_stack_free(stack);
}

void test_pam_stack_parse__comments(void **state)
{
    struct pam_stack *stack;
    errno_t ret;

    ret = pam_stack_parse(__FUNCTION__, &stack);
    assert_int_equal(ret, EOK);

    assert_pam_line(stack, "auth sufficient pam_sss.so forward_pass", false,
                    "auth", "sufficient", "pam_sss.so", "forward_pass");
    assert_null(stack->prev);
    assert_null(stack->next);

    pam_stack_free(stack);
}

void test_pam_stack_parse__spaces(void **state)
{
    struct pam_stack *stack;
    errno_t ret;

    ret = pam_stack_parse(__FUNCTION__, &stack);
    assert_int_equal(ret, EOK);

    assert_pam_line(stack, "auth sufficient pam_sss.so forward_pass", false,
                    "auth", "sufficient", "pam_sss.so", "forward_pass");
    assert_null(stack->prev);
    assert_null(stack->next);

    pam_stack_free(stack);
}

void test_pam_stack_parse__phases(void **state)
{
    struct pam_stack *stack;
    struct pam_stack *line;
    errno_t ret;

    ret = pam_stack_parse(__FUNCTION__, &stack);
    assert_int_equal(ret, EOK);

    line = stack;
    assert_pam_line(line, "account required pam_unix.so", false,
                        "account", "required", "pam_unix.so", "");
    assert_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "auth sufficient pam_sss.so forward_pass", false,
                        "auth", "sufficient", "pam_sss.so", "forward_pass");
    assert_non_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "password requisite pam_pwquality.so try_first_pass local_users_only", false,
                    "password", "requisite", "pam_pwquality.so", "try_first_pass local_users_only");
    assert_non_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "session optional pam_keyinit.so revoke", false,
                    "session", "optional", "pam_keyinit.so", "revoke");
    assert_non_null(line->prev);
    assert_null(line->next);

    pam_stack_free(stack);
}

void test_pam_stack_parse__invalid_phase(void **state)
{
    struct pam_stack *stack;
    errno_t ret;

    ret = pam_stack_parse(__FUNCTION__, &stack);
    assert_int_equal(ret, EBADMSG);
}

void test_pam_stack_parse__invalid_action(void **state)
{
    struct pam_stack *stack;
    errno_t ret;

    ret = pam_stack_parse(__FUNCTION__, &stack);
    assert_int_equal(ret, EBADMSG);
}

void test_pam_stack_parse__invalid_file(void **state)
{
    struct pam_stack *stack;
    errno_t ret;

    ret = pam_stack_parse(__FUNCTION__, &stack);
    assert_int_equal(ret, EACCES);
}

void test_pam_stack_parse__include_single_line(void **state)
{
    struct pam_stack *stack;
    errno_t ret;

    ret = pam_stack_parse(__FUNCTION__, &stack);
    assert_int_equal(ret, EOK);

    assert_pam_line(stack, "account required pam_unix.so", false,
                    "account", "required", "pam_unix.so", "");
    assert_null(stack->prev);
    assert_null(stack->next);

    pam_stack_free(stack);
}

void test_pam_stack_parse__include_phases(void **state)
{
    struct pam_stack *stack;
    struct pam_stack *line;
    errno_t ret;

    ret = pam_stack_parse(__FUNCTION__, &stack);
    assert_int_equal(ret, EOK);

    line = stack;
    assert_pam_line(line, "account required pam_unix.so", false,
                    "account", "required", "pam_unix.so", "");
    assert_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "auth sufficient pam_sss.so forward_pass", false,
                    "auth", "sufficient", "pam_sss.so", "forward_pass");
    assert_non_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "password requisite pam_pwquality.so try_first_pass local_users_only", false,
                    "password", "requisite", "pam_pwquality.so", "try_first_pass local_users_only");
    assert_non_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "session optional pam_keyinit.so revoke", false,
                    "session", "optional", "pam_keyinit.so", "revoke");
    assert_non_null(line->prev);
    assert_null(line->next);

    pam_stack_free(stack);
}

void test_pam_stack_parse__include_mixed(void **state)
{
    struct pam_stack *stack;
    struct pam_stack *line;
    errno_t ret;

    ret = pam_stack_parse(__FUNCTION__, &stack);
    assert_int_equal(ret, EOK);

    line = stack;
    assert_pam_line(line, "account required pam_unix.so", false,
                    "account", "required", "pam_unix.so", "");
    assert_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "auth sufficient pam_pre.so", false,
                    "auth", "sufficient", "pam_pre.so", "");
    assert_non_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "auth sufficient pam_sss.so forward_pass", false,
                    "auth", "sufficient", "pam_sss.so", "forward_pass");
    assert_non_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "auth sufficient pam_post.so", false,
                    "auth", "sufficient", "pam_post.so", "");
    assert_non_null(line->prev);
    assert_non_null(line->next);


    line = line->next;
    assert_pam_line(line, "password requisite pam_pwquality.so try_first_pass local_users_only", false,
                    "password", "requisite", "pam_pwquality.so", "try_first_pass local_users_only");
    assert_non_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "session optional pam_keyinit.so revoke", false,
                    "session", "optional", "pam_keyinit.so", "revoke");
    assert_non_null(line->prev);
    assert_null(line->next);

    pam_stack_free(stack);
}

void test_pam_stack_parse__substack_single_line(void **state)
{
    struct pam_stack *stack;
    errno_t ret;

    ret = pam_stack_parse(__FUNCTION__, &stack);
    assert_int_equal(ret, EOK);

    assert_pam_line(stack, "account required pam_unix.so", false,
                    "account", "required", "pam_unix.so", "");
    assert_null(stack->prev);
    assert_null(stack->next);

    pam_stack_free(stack);
}

void test_pam_stack_parse__substack_phases(void **state)
{
    struct pam_stack *stack;
    struct pam_stack *line;
    errno_t ret;

    ret = pam_stack_parse(__FUNCTION__, &stack);
    assert_int_equal(ret, EOK);

    line = stack;
    assert_pam_line(line, "account required pam_unix.so", false,
                    "account", "required", "pam_unix.so", "");
    assert_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "auth sufficient pam_sss.so forward_pass", false,
                    "auth", "sufficient", "pam_sss.so", "forward_pass");
    assert_non_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "password requisite pam_pwquality.so try_first_pass local_users_only", false,
                    "password", "requisite", "pam_pwquality.so", "try_first_pass local_users_only");
    assert_non_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "session optional pam_keyinit.so revoke", false,
                    "session", "optional", "pam_keyinit.so", "revoke");
    assert_non_null(line->prev);
    assert_null(line->next);

    pam_stack_free(stack);
}

void test_pam_stack_parse__substack_mixed(void **state)
{
    struct pam_stack *stack;
    struct pam_stack *line;
    errno_t ret;

    ret = pam_stack_parse(__FUNCTION__, &stack);
    assert_int_equal(ret, EOK);

    line = stack;
    assert_pam_line(line, "account required pam_unix.so", false,
                    "account", "required", "pam_unix.so", "");
    assert_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "auth sufficient pam_pre.so", false,
                    "auth", "sufficient", "pam_pre.so", "");
    assert_non_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "auth sufficient pam_sss.so forward_pass", false,
                    "auth", "sufficient", "pam_sss.so", "forward_pass");
    assert_non_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "auth sufficient pam_post.so", false,
                    "auth", "sufficient", "pam_post.so", "");
    assert_non_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "password requisite pam_pwquality.so try_first_pass local_users_only", false,
                    "password", "requisite", "pam_pwquality.so", "try_first_pass local_users_only");
    assert_non_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "session optional pam_keyinit.so revoke", false,
                    "session", "optional", "pam_keyinit.so", "revoke");
    assert_non_null(line->prev);
    assert_null(line->next);

    pam_stack_free(stack);
}

void test_pam_stack_parse__include_substack(void **state)
{
    struct pam_stack *stack;
    struct pam_stack *line;
    errno_t ret;

    ret = pam_stack_parse(__FUNCTION__, &stack);
    assert_int_equal(ret, EOK);

    line = stack;
    assert_pam_line(line, "account required pam_unix.so", false,
                    "account", "required", "pam_unix.so", "");
    assert_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "auth sufficient pam_sss.so forward_pass", false,
                    "auth", "sufficient", "pam_sss.so", "forward_pass");
    assert_non_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "password requisite pam_pwquality.so try_first_pass local_users_only", false,
                    "password", "requisite", "pam_pwquality.so", "try_first_pass local_users_only");
    assert_non_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "session optional pam_keyinit.so revoke", false,
                    "session", "optional", "pam_keyinit.so", "revoke");
    assert_non_null(line->prev);
    assert_null(line->next);

    pam_stack_free(stack);
}

void test_pam_stack_parse__loop(void **state)
{
    struct pam_stack *stack;
    errno_t ret;

    ret = pam_stack_parse(__FUNCTION__, &stack);
    assert_int_equal(ret, ELOOP);
}

void test_pam_stack_parse__paths(void **state)
{
    struct pam_stack *stack;
    struct pam_stack *line;
    errno_t ret;

    ret = pam_stack_parse("/etc/pam.d/system-auth", &stack);
    assert_int_equal(ret, EOK);

    line = stack;
    assert_pam_line(line, "account required pam_unix.so", false,
                    "account", "required", "pam_unix.so", "");
    assert_null(line->prev);
    assert_non_null(line->next);

    line = line->next;
    assert_pam_line(line, "auth required pam_sss.so", false,
                    "auth", "required", "pam_sss.so", "");
    assert_non_null(line->prev);
    assert_null(line->next);

    pam_stack_free(stack);
}

int main(int argc, const char *argv[])
{

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_pam_stack_parse__single_line),
        cmocka_unit_test(test_pam_stack_parse__silent),
        cmocka_unit_test(test_pam_stack_parse__no_params),
        cmocka_unit_test(test_pam_stack_parse__two_lines),
        cmocka_unit_test(test_pam_stack_parse__brackets),
        cmocka_unit_test(test_pam_stack_parse__comments),
        cmocka_unit_test(test_pam_stack_parse__spaces),
        cmocka_unit_test(test_pam_stack_parse__phases),
        cmocka_unit_test(test_pam_stack_parse__invalid_phase),
        cmocka_unit_test(test_pam_stack_parse__invalid_action),
        cmocka_unit_test(test_pam_stack_parse__invalid_file),
        cmocka_unit_test(test_pam_stack_parse__include_single_line),
        cmocka_unit_test(test_pam_stack_parse__include_phases),
        cmocka_unit_test(test_pam_stack_parse__include_mixed),
        cmocka_unit_test(test_pam_stack_parse__substack_single_line),
        cmocka_unit_test(test_pam_stack_parse__substack_phases),
        cmocka_unit_test(test_pam_stack_parse__substack_mixed),
        cmocka_unit_test(test_pam_stack_parse__include_substack),
        cmocka_unit_test(test_pam_stack_parse__loop),
        cmocka_unit_test(test_pam_stack_parse__paths),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
