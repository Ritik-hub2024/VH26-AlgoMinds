"""Example: Valid Python syntax with potential resource leaks for future analyzer rules."""

def read_log_unclosed(file_path: str) -> str:
    # Notice: open() called without with-statement context manager
    f = open(file_path, "r", encoding="utf-8")
    content = f.read()
    # Missing f.close() in exception paths or return
    return content


def connect_unclosed_socket(host: str, port: int) -> None:
    import socket

    # Raw socket allocation without context manager or try/finally close
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.sendall(b"PING")
