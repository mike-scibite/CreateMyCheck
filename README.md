# GitHub App Check Run toy project

The pull-request workflow in [`.github/workflows/toy-file-check.yml`](.github/workflows/toy-file-check.yml) reads the PR's version of `check_result.txt`, obtains a short-lived GitHub App installation token, and calls the Checks REST API with `curl`.

`check_result.txt` controls the Check Run conclusion:

| File value | Conclusion |
| --- | --- |
| `success` or `pass` | `success` |
| `failure` or `fail` | `failure` |
| missing or any other value | `neutral` |

## One-time GitHub setup

1. In the GitHub App's **Permissions & events**, keep **Checks: Read and write**. No webhook subscription is needed for this workflow.
2. Generate a private key under the App's **Private keys** section. Downloaded keys are PEM files; GitHub only lets you download each one once.
3. Install the App on the account or organisation that owns this repository, and grant it access to this repository. The workflow looks up that installation automatically, so there is no installation-ID secret.
4. In this repository's **Settings → Secrets and variables → Actions**, add:
   - Secret `TOY_CHECK_APP_PRIVATE_KEY`: the complete PEM file, including `BEGIN`/`END` lines and line breaks.
   - Secret `TOY_CHECK_APP_ID`: the numeric App ID displayed on the App's settings page.

The App ID is public metadata, but this toy project keeps it alongside the private key as an Actions secret. Do **not** add the App's client secret: it is for the OAuth user-token flow and this workflow uses an installation token instead. Do not add a webhook secret either, because this project does not receive webhooks.

For a toy project installed only on your own account or organisation, you do not need to publish the App for public installation. Limit the installation to this repository. Keep the private key only in Actions secrets and rotate/delete it if it is exposed.

## Try it

Create a branch, change `check_result.txt`, and open a pull request. The Check Run is attached to the PR head commit and appears as **Toy file check**. This workflow intentionally skips fork pull requests because GitHub withholds repository secrets from them.

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
        │ token scoped to this repository, Checks: write
        ▼
POST /repos/{owner}/{repo}/check-runs
```

The REST endpoints and required Checks permission are documented by GitHub: [creating check runs](https://docs.github.com/en/rest/checks/runs#create-a-check-run), [authenticating as an installation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation), and [using secrets safely with fork PRs](https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions).
