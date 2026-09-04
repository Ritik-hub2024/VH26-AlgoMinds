"""
LeakGuard Dashboard Server & Runner

Starts a local HTTP server serving the frontend dashboard
and provides live scan results.
"""

import http.server
import socketserver
import webbrowser
from pathlib import Path

HOST = "127.0.0.1"
DEFAULT_PORT = 8000
FRONTEND_DIR = Path(__file__).resolve().parent / "frontend"


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)


def find_server(host: str = HOST, start_port: int = DEFAULT_PORT, max_attempts: int = 20):
    for port in range(start_port, start_port + max_attempts):
        try:
            server = ReusableTCPServer((host, port), Handler)
            return server, port
        except OSError as e:
            if "Address already in use" in str(e) or getattr(e, "errno", None) in (48, 98, 10048, 10013):
                continue
            raise
    raise RuntimeError(f"Could not find an available port between {start_port} and {start_port + max_attempts - 1}")


def main():
    try:
        httpd, port = find_server(host=HOST, start_port=DEFAULT_PORT)
    except Exception as e:
        print(f"[!] Error starting server: {e}")
        return 1

    url = f"http://localhost:{port}"
    print("=" * 60)
    print("  [LeakGuard] Web Dashboard Server")
    print("=" * 60)
    print(f"Serving dashboard from: {FRONTEND_DIR}")
    print(f"Dashboard URL:          {url}")
    print("Press Ctrl+C to stop the server.")
    print("=" * 60)

    try:
        webbrowser.open(url)
    except Exception:
        pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping LeakGuard server...")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    main()
