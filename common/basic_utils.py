import select
import sys


def check_for_user_quit():
    user_quit = False

    while True:
        rlist, _, _ = select.select([sys.stdin], [], [], 0)
        if rlist:
            char = sys.stdin.read(1)
            if char.lower() == 'q':
                user_quit = True
        else:
            break

    if user_quit:
        print('User requested quit...')

    return user_quit