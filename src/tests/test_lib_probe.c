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
#include "authselect.h"

errno_t
textfile_read(const char *filepath,
              unsigned int limit_KiB,
              char **_content)
{
    const char *stack;
    char *content;

    stack = mock_ptr_type(const char *);
    assert_non_null(stack);

    content = strdup(stack);
    assert_non_null(content);

    *_content = content;

    return EOK;
}

void test_authselect_probe_enabled__pam_unix_nullok__enabled(void **state)
{
    bool enabled;
    int ret;

    will_return_always(textfile_read, "auth sufficient pam_unix.so nullok try_first_pass");
    ret = authselect_probe_enabled(AUTHSELECT_PROBE_PAM_UNIX_NULLOK, &enabled);
    assert_int_equal(ret, EOK);
    assert_true(enabled);
}

void test_authselect_probe_enabled__pam_unix_nullok__disabled(void **state)
{
    bool enabled;
    int ret;

    will_return_count(textfile_read, "auth sufficient pam_unix.so try_first_pass", 4);
    ret = authselect_probe_enabled(AUTHSELECT_PROBE_PAM_UNIX_NULLOK, &enabled);
    assert_int_equal(ret, EOK);
    assert_false(enabled);

    will_return_count(textfile_read, "auth sufficient pam_unix.so null ok try_first_pass", 4);
    ret = authselect_probe_enabled(AUTHSELECT_PROBE_PAM_UNIX_NULLOK, &enabled);
    assert_int_equal(ret, EOK);
    assert_false(enabled);

    will_return_count(textfile_read, "auth sufficient pam_unix.so nullresetok try_first_pass", 4);
    ret = authselect_probe_enabled(AUTHSELECT_PROBE_PAM_UNIX_NULLOK, &enabled);
    assert_int_equal(ret, EOK);
    assert_false(enabled);
}

void test_authselect_probe_enabled__pam_unix_nullok__missing(void **state)
{
    bool enabled;
    int ret;

    will_return_always(textfile_read, "auth sufficient pam_sss.so");
    ret = authselect_probe_enabled(AUTHSELECT_PROBE_PAM_UNIX_NULLOK, &enabled);
    assert_int_equal(ret, ENOENT);
}

void test_authselect_probe_enabled__pam_unix_nullok__invalid(void **state)
{
    bool enabled;
    int ret;

    will_return_always(textfile_read, "authentication sufficient pam_sss.so");
    ret = authselect_probe_enabled(AUTHSELECT_PROBE_PAM_UNIX_NULLOK, &enabled);
    assert_int_equal(ret, EBADMSG);
}

int main(int argc, const char *argv[])
{

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_authselect_probe_enabled__pam_unix_nullok__enabled),
        cmocka_unit_test(test_authselect_probe_enabled__pam_unix_nullok__disabled),
        cmocka_unit_test(test_authselect_probe_enabled__pam_unix_nullok__missing),
        cmocka_unit_test(test_authselect_probe_enabled__pam_unix_nullok__invalid),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
