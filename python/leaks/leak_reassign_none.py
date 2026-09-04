"""Adversarial Leak Case: Active resource overwritten with None."""


def reset_active_handle():
    f = open("session.lock", "w")
    # LEAK: Overwriting open handle with None loses the resource pointer
    f = None
    return "handle_cleared"
