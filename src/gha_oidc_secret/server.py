"""OIDC token validator server for GitHub Actions tokens."""

from __future__ import annotations

import argparse
import json
import sys
from functools import partial
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import urlopen
from urllib.error import URLError

import jwt
from jwt.algorithms import RSAAlgorithm

# GitHub OIDC configuration
GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_JWKS_URL = f"{GITHUB_OIDC_ISSUER}/.well-known/jwks"

# Cache for JWKS keys
_JWKS_CACHE = None


def fetch_jwks() -> dict[str, object]:
    """
    Fetch GitHub's JWKS (JSON Web Key Set) for token validation.

    Returns:
        The JWKS data containing public keys

    Raises:
        URLError: If fetching JWKS fails
    """
    global _JWKS_CACHE

    if _JWKS_CACHE is not None:
        return _JWKS_CACHE

    try:
        with urlopen(GITHUB_JWKS_URL, timeout=10) as response:
            _JWKS_CACHE = json.loads(response.read().decode("utf-8"))
            return _JWKS_CACHE
    except URLError as e:
        raise Exception(f"Failed to fetch JWKS from {GITHUB_JWKS_URL}: {e}")


def get_signing_key_from_jwt(token: str) -> object:
    """
    Get the signing key from GitHub's JWKS that matches the token's kid.

    Args:
        token: The JWT token

    Returns:
        The RSA public key for verification

    Raises:
        Exception: If no matching key is found
    """
    # Decode header without verification to get the key ID
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")

    if not kid:
        raise Exception("Token header missing 'kid' field")

    # Fetch JWKS
    jwks = fetch_jwks()

    # Find the matching key
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            # Convert JWK to RSA public key
            return RSAAlgorithm.from_jwk(json.dumps(key))

    raise Exception(f"No signing key found for kid: {kid}")


def validate_github_oidc_token(token: str) -> dict[str, object]:
    """
    Validate a GitHub Actions OIDC token.

    Args:
        token: The JWT token from GitHub Actions

    Returns:
        The decoded token claims

    Raises:
        jwt.InvalidTokenError: If token validation fails
    """
    # Get signing key
    signing_key = get_signing_key_from_jwt(token)

    # Decode and validate the token
    decoded_token = jwt.decode(
        token,
        signing_key,
        algorithms=["RS256"],
        issuer=GITHUB_OIDC_ISSUER,
        options={
            "verify_signature": True,
            "verify_exp": True,
            "verify_iss": True,
            "verify_aud": True,
        },
    )

    return decoded_token


def verify_repository_claims(
    claims: dict[str, object],
    allowed_repo: str | None = None,
    allowed_owner: str | None = None,
) -> tuple[bool, str]:
    """
    Verify that the token claims match the allowed repository.

    Args:
        claims: The decoded token claims
        allowed_repo: Optional allowed repository in format 'owner/repo'
        allowed_owner: Optional allowed repository owner/organization

    Returns:
        Tuple of (is_valid, message)
    """
    # Check repository claim
    repository = claims.get("repository")
    if not repository:
        return False, "Missing 'repository' claim"

    # Check repository owner
    repository_owner = claims.get("repository_owner")
    if not repository_owner:
        return False, "Missing 'repository_owner' claim"

    # Verify against allowed values
    if allowed_repo and repository != allowed_repo:
        return False, f"Repository mismatch: expected '{allowed_repo}', got '{repository}'"

    if allowed_owner and repository_owner != allowed_owner:
        return False, f"Owner mismatch: expected '{allowed_owner}', got '{repository_owner}'"

    return True, "Repository claims verified"


def print_token_claims(claims: dict[str, object]) -> None:
    """Pretty print all token claims."""
    print("\n" + "=" * 80)
    print("GITHUB ACTIONS OIDC TOKEN CLAIMS")
    print("=" * 80)

    print("\nClaims:")
    print("-" * 80)
    print(json.dumps(claims, indent=2))
    print("=" * 80 + "\n")


class OIDCValidatorHandler(BaseHTTPRequestHandler):
    """HTTP request handler for OIDC token validation."""

    def __init__(
        self,
        *args,
        allowed_repo: str | None = None,
        allowed_owner: str | None = None,
        **kwargs,
    ):
        """
        Initialize the handler with optional repository restrictions.

        Args:
            allowed_repo: Optional allowed repository in format 'owner/repo'
            allowed_owner: Optional allowed repository owner/organization
        """
        self.allowed_repo = allowed_repo
        self.allowed_owner = allowed_owner
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        """Override to customize logging format."""
        # Only log errors, not every request
        if self.command:
            pass

    def _send_json_response(self, status_code: int, data: dict):
        """Send a JSON response."""
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_GET(self):
        """Handle GET requests."""
        if self.path == "/health":
            self._send_json_response(200, {"status": "healthy"})
        else:
            self._send_json_response(404, {"error": "Not found"})

    def do_POST(self):
        """Handle POST requests."""
        if self.path != "/validate":
            self._send_json_response(404, {"error": "Not found"})
            return

        try:
            # Read request body
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)

            # Parse JSON
            try:
                data = json.loads(body.decode("utf-8"))
            except json.JSONDecodeError:
                self._send_json_response(400, {"error": "Invalid JSON in request body"})
                return

            # Get token from request
            if not data or "token" not in data:
                self._send_json_response(400, {"error": "Missing 'token' in request body"})
                return

            token = data["token"]

            # Validate the token
            print("\nReceived token validation request...")
            claims = validate_github_oidc_token(token)

            # Verify repository claims
            is_valid, message = verify_repository_claims(
                claims,
                allowed_repo=self.allowed_repo,
                allowed_owner=self.allowed_owner,
            )
            if not is_valid:
                print(f"[FAIL] Validation failed: {message}")
                self._send_json_response(403, {"error": message})
                return

            # Print all claims
            print(f"[SUCCESS] {message}")
            print_token_claims(claims)

            self._send_json_response(
                200, {"status": "success", "message": message, "claims": claims}
            )

        except jwt.ExpiredSignatureError:
            error = "Token has expired"
            print(f"[ERROR] {error}")
            self._send_json_response(401, {"error": error})
        except jwt.InvalidTokenError as e:
            error = f"Invalid token: {str(e)}"
            print(f"[ERROR] {error}")
            self._send_json_response(401, {"error": error})
        except Exception as e:
            error = f"Unexpected error: {str(e)}"
            print(f"[ERROR] {error}")
            self._send_json_response(500, {"error": error})


def main():
    """Run the OIDC validator server."""
    parser = argparse.ArgumentParser(description="GitHub Actions OIDC token validator")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind to (default: 5000)")

    # Create mutually exclusive group for repository restrictions
    repo_group = parser.add_mutually_exclusive_group()
    repo_group.add_argument(
        "--allowed-repo",
        metavar="OWNER/REPO",
        help="Allowed repository in format 'owner/repo' (e.g., 'octocat/hello-world')",
    )
    repo_group.add_argument(
        "--allowed-owner",
        metavar="OWNER",
        help="Allowed repository owner/organization (e.g., 'octocat')",
    )

    args = parser.parse_args()

    # Validate --allowed-repo format if provided
    if args.allowed_repo and "/" not in args.allowed_repo:
        parser.error("--allowed-repo must be in format 'owner/repo'")

    print("Starting GitHub Actions OIDC Validator Server")
    print(f"Listening on: http://{args.host}:{args.port}")

    if args.allowed_repo:
        print(f"Allowed repository: {args.allowed_repo}")
    if args.allowed_owner:
        print(f"Allowed owner: {args.allowed_owner}")

    print("\nEndpoints:")
    print(f"  POST http://{args.host}:{args.port}/validate - Validate OIDC token")
    print(f"  GET  http://{args.host}:{args.port}/health   - Health check")
    print("\nWaiting for requests...\n")

    # Create configured handler and start server
    handler = partial(
        OIDCValidatorHandler,
        allowed_repo=args.allowed_repo,
        allowed_owner=args.allowed_owner,
    )
    server = HTTPServer((args.host, args.port), handler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\nShutting down server...")
        server.shutdown()
        sys.exit(0)


if __name__ == "__main__":
    main()
