# GitHub App JFrog security scan

The pull-request workflow in [`.github/workflows/toy-file-check.yml`](.github/workflows/toy-file-check.yml) reads the PR's JFrog-style `check_result.txt`, obtains a short-lived GitHub App installation token, and calls GitHub's REST API with `curl`.

The workflow counts the severity cells in the **Vulnerable Components** table and posts the totals in both a pull-request comment and the Check Run summary:

| Severity | Symbol |
| --- | --- |
| Critical | 🚨 |
| High | 🔴 |
| Medium | 🟠 |
| Low | 🟡 |
| Unknown | ⚪ |

Critical findings create a failed Check Run and fail the workflow. If there are no Critical findings but one or more High findings, the Check Run is marked `action_required` to request attention; the workflow itself succeeds. All other results produce a successful Check Run.

## One-time GitHub setup

1. In the GitHub App's **Permissions & events**, grant **Checks: Read and write** and **Pull requests: Read and write**. No webhook subscription is needed for this workflow. The Pull requests permission allows the app to comment on pull requests.
2. Generate a private key under the App's **Private keys** section. Downloaded keys are PEM files; GitHub only lets you download each one once.
3. Install the App on the account or organisation that owns this repository, and grant it access to this repository. The workflow looks up that installation automatically, so there is no installation-ID secret.
4. In this repository's **Settings → Secrets and variables → Actions**, add:
   - Secret `TOY_CHECK_APP_PRIVATE_KEY`: the complete PEM file, including `BEGIN`/`END` lines and line breaks.
   - Secret `TOY_CHECK_APP_ID`: the numeric App ID displayed on the App's settings page.

The App ID is public metadata, but this toy project keeps it alongside the private key as an Actions secret. Do **not** add the App's client secret: it is for the OAuth user-token flow and this workflow uses an installation token instead. Do not add a webhook secret either, because this project does not receive webhooks.

For a toy project installed only on your own account or organisation, you do not need to publish the App for public installation. Limit the installation to this repository. Keep the private key only in Actions secrets and rotate/delete it if it is exposed.

## Try it

Create a branch, change `check_result.txt`, and open a pull request. The Check Run is attached to the PR head commit and appears as **JFrog security scan**. This workflow intentionally skips fork pull requests because GitHub withholds repository secrets from them.

The workflow checks out untrusted PR content only to read a text file; it never executes content from the PR. Treat contributors who can open branches in this repository as trusted, because same-repository PR workflows can receive this App private-key secret.

## Authentication flow

```
App ID + private PEM
        │ sign a short-lived JWT
        ▼
GET /repos/{owner}/{repo}/installation
        │ installation ID
        ▼
POST /app/installations/{id}/access_tokens
        │ token scoped to this repository, Checks + Issues: write
        ▼
POST /repos/{owner}/{repo}/check-runs
        │
        ▼
POST /repos/{owner}/{repo}/issues/{pr_number}/comments
```

The REST endpoints and required Checks permission are documented by GitHub: [creating check runs](https://docs.github.com/en/rest/checks/runs#create-a-check-run), [authenticating as an installation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation), and [using secrets safely with fork PRs](https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions).

## Local Java API reproducer

The Maven project in this repository performs the same GitHub App authentication flow using Java 17's HTTP and cryptography APIs. It reads the downloaded PKCS#1 PEM key directly; it never prints the private key, JWT, or installation token.

Build it and authenticate without creating a comment:

```bash
mvn clean verify
mvn -q exec:java -Dexec.args='--dry-run'
```

Post a test comment to PR #1:

```bash
mvn -q exec:java \
  -Dexec.args='--pr 1 --body "Local Java GitHub App API test (safe to delete)."'
```

Defaults are set for this test repository and App:

- App ID: `4909825` (public GitHub App metadata)
- Repository: `mike-scibite/CreateMyCheck`
- PR: `1`
- Private key: `.secret/create-my-check.2026-09-11.private-key.pem`
- Installation-token permission: `pull_requests:write`

Every default can be overridden with `--app-id`, `--private-key`, `--repo`, `--pr`, `--body`, `--api-url`, or `--token-permission`.

### Finding from the local reproduction

On 17 September 2026, GitHub returned `403 Resource not accessible by integration` when this App called the issue-comment endpoint with an installation token narrowed to `issues:write`. The response's `X-Accepted-GitHub-Permissions` header listed both `issues=write` and `pull_requests=write`, consistent with the REST documentation, but retrying with a token narrowed to `pull_requests:write` succeeded. The workflow therefore requests `pull_requests:write` for PR comments. `--token-permission issues` remains available in the Java client to reproduce the failing behavior.
