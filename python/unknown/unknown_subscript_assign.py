"""Unknown Case: Resource stored into dictionary mapping by subscript."""


def register_global_handle(registry: dict):
    f = open("active_session.io", "r")
    # Escapes to collection container via subscript assignment
    registry["primary_stream"] = f
    return registry
