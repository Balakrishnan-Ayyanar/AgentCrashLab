"""Check the installed offline loopback service. Does not submit any evaluation."""
import argparse
import getpass
import json
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

ORIGIN = "http://127.0.0.1:18081"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def check(authenticated):
    opener = build_opener(ProxyHandler({}), NoRedirect())

    def get(path, token=None):
        headers = {"Authorization": "Bearer " + token} if token else {}
        try:
            with opener.open(Request(ORIGIN + path, headers=headers), timeout=3) as response:
                return response.status, json.loads(response.read(8192))
        except HTTPError as exc:
            return exc.code, {}

    if get("/api/health") != (200, {"status": "ok", "mode": "offline"}):
        raise RuntimeError("Expected an offline loopback service on port 18081")
    if get("/api/config/public") != (200, {"mode": "offline", "auth_required": True}):
        raise RuntimeError("Unexpected public configuration")
    expected = 401 if authenticated else 403
    if get("/api/ready")[0] != expected:
        raise RuntimeError("Protected readiness did not deny unauthenticated access")
    if authenticated:
        token = getpass.getpass("Private synthetic workspace token: ")
        if not token:
            raise RuntimeError("A private workspace token is required for this check")
        status, readiness = get("/api/ready", token)
        if status != 200 or readiness != {"mode": "offline", "ready": True, "docker": False,
                                          "inference_configured": False, "inference_success_observed": False}:
            raise RuntimeError("Unexpected authenticated readiness")
    print("Private offline health and fail-closed authentication verified")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authenticated", action="store_true", help="Check a token-configured private service")
    check(parser.parse_args().authenticated)
