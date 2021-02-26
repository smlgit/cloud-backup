import os
import datetime


# Global that you can modify to conditionally run slow tests.
run_slow_tests = True


def make_random_file(full_path, num_bytes, leave_existing=False,
                     modify_timestamp_ns=None):
    if leave_existing is False or os.path.exists(full_path) is False:
        with open(full_path, 'wb') as f:
            f.write(os.urandom(num_bytes))

        if modify_timestamp_ns is not None:
            os.utime(full_path,
                     ns=(int(datetime.datetime.utcnow().timestamp() * 1000000000),
                         modify_timestamp_ns))
