"""Unknown Case: Resource transferred via keyword argument."""


def dispatch_job(task_id: int, target_file=None):
    pass


def execute_background_job():
    f = open("job_input.txt", "r")
    # Transferred via keyword argument to external callee
    dispatch_job(task_id=42, target_file=f)
    return "scheduled"
