# GitHub Actions OIDC Secret Validator

A Python server that validates GitHub Actions OIDC tokens and demonstrates secure authentication between GitHub Actions workflows and external services.
This is only used as a POC to see what needs to be done to use OIDC authentication with a custom secret server.

## Overview

This project demonstrates how to:
- Request OIDC tokens from GitHub Actions workflows
- Validate GitHub-issued JWT tokens using their public keys
- Verify repository and organization claims to ensure tokens come from trusted sources
- Extract and inspect all available claims from GitHub OIDC tokens

## Requirements

- Python 3.11 or higher
- [uv](https://github.com/astral-sh/uv) (recommended) or pip
- A GitHub repository with Actions enabled

## Installation

### Using uv

```bash
uv sync
```

## Usage

### Running the OIDC Validator Server

Start the server with repository restrictions:

```bash
# Basic usage (accepts tokens from any repository)
uv run python -m gha_oidc_secret.server

# Restrict to specific repository
uv run python -m gha_oidc_secret.server --allowed-repo "yourusername/yourrepo"

# Restrict to specific organization/owner
uv run python -m gha_oidc_secret.server --allowed-owner "yourorg"

# Custom host and port
uv run python -m gha_oidc_secret.server --host 0.0.0.0 --port 8080
```

The server will start on `http://127.0.0.1:5000` by default and provide two endpoints:
- `POST /validate` - Validates OIDC tokens
- `GET /health` - Health check endpoint
