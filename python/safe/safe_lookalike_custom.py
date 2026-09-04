"""Adversarial Safe Case: Custom wrapper functions that are not tracked system resources."""


def load_application_state():
    # Looks like a resource call but is a domain wrapper / helper
    config = custom_open_wrapper("app_state.json")
    cache = get_cached_handle("session_store")
    return {"config": config, "cache": cache}


def custom_open_wrapper(name: str):
    return f"mock_state_{name}"


def get_cached_handle(key: str):
    return [key, "active"]
