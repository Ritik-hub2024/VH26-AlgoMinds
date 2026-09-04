"""Unknown Case: Resource added to container using extend()."""


def enqueue_file_handles(pool: list):
    f = open("queue.msg", "r")
    # Escapes to collection container via extend
    pool.extend([f])
    return len(pool)
