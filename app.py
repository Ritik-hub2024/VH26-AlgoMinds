"""
LeakGuard Dashboard Server & Runner

Starts a local HTTP server serving the frontend dashboard
and provides live scan results.
"""

import http.server
import json
import os
import socketserver
import sys
import urllib.parse
import webbrowser
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import cli

HOST = "127.0.0.1"
DEFAULT_PORT = 8000
FRONTEND_DIR = ROOT_DIR / "frontend"


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/scan":
            self._handle_api_scan(parsed.query)
            return
        super().do_GET()

    def _handle_api_scan(self, query_str: str):
        qs = urllib.parse.parse_qs(query_str)
        target = qs.get("target", ["python"])[0]

        # Resolve target safely within workspace
        target_path = (ROOT_DIR / target).resolve()
        if not target_path.exists():
            target_path = Path(target).resolve()

        if not target_path.exists():
            self._send_json(
                {
                    "error": f"Target path '{target}' does not exist.",
                    "status": "ERROR",
                    "files_scanned": 0,
                    "clean_files": 0,
                    "syntax_errors": 0,
                    "leaks_detected": 0,
                    "findings": [],
                },
                status=404,
            )
            return

        try:
            report = cli.scan_target(str(target_path))
            data = report.to_dict()
            data["status"] = "PASS" if not report.has_errors_or_issues else "FAILED"
            data["files_scanned"] = report.files_scanned
            data["clean_files"] = report.clean_files_count
            data["syntax_errors_count"] = len(report.syntax_errors)
            data["leaks_detected"] = len(report.issues)

            # Build normalized findings adhering to data contract
            findings = []
            for issue in report.issues:
                try:
                    rel_file = Path(issue.location.file_path).relative_to(ROOT_DIR).as_posix()
                except Exception:
                    rel_file = issue.location.file_path

                findings.append({
                    "rule_id": issue.rule_id,
                    "severity": issue.severity.value if hasattr(issue.severity, "value") else str(issue.severity),
                    "file": rel_file,
                    "line": issue.location.line,
                    "resource": f"{issue.resource_name} ({issue.resource_type})" if issue.resource_name else (issue.resource_type or "Resource"),
                    "resource_name": issue.resource_name,
                    "resource_type": issue.resource_type,
                    "reason": issue.problem or issue.message,
                    "leak_path": issue.leak_path or "",
                    "recommendation": issue.recommendation or "",
                    "function_name": issue.function_name or "",
                })
            data["findings"] = findings

            # Also update frontend/report.json so static / file access remains fresh
            try:
                report_file = FRONTEND_DIR / "report.json"
                with open(report_file, "w", encoding="utf-8") as rf:
                    json.dump(data, rf, indent=2)
            except Exception:
                pass

            self._send_json(data)
        except Exception as exc:
            self._send_json({"error": str(exc), "status": "ERROR"}, status=500)

    def _send_json(self, payload: dict, status: int = 200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


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

    if "--no-browser" not in sys.argv:
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
