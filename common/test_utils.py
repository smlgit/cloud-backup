import os


# Global that you can modify to conditionally run slow tests.
run_slow_tests = False


def make_random_file(full_path, num_bytes, leave_existing=False):
    if leave_existing is False or os.path.exists(full_path) is False:
        with open(full_path, 'wb') as f:
            f.write(os.urandom(num_bytes))