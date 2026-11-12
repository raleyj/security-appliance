import json
import ssl
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


http = urllib.request.build_opener(NoRedirect())
try:
    http.open("http://security.example.local/admin/", timeout=8)
    raise RuntimeError("HTTP request did not redirect")
except urllib.error.HTTPError as error:
    redirect = {
        "status": error.code,
        "location": error.headers.get("Location"),
    }

context = ssl._create_unverified_context()
with urllib.request.urlopen(
    "https://security.example.local/admin/", context=context, timeout=8
) as response:
    https_status = response.status

result = {
    "http": redirect,
    "httpsStatus": https_status,
    "passed": redirect == {
        "status": 308,
        "location": "https://security.example.local/admin/",
    }
    and https_status == 200,
}
print(json.dumps(result, indent=2))
if not result["passed"]:
    raise SystemExit(1)
