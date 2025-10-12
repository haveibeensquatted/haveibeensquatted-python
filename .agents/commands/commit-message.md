# Conventional Commit Helper (staged changes only)

Use this helper to propose a Conventional Commit message based on **staged**
changes. Do not create a commit. Do not modify any files. Only output the
recommended commit message.

Spec: https://www.conventionalcommits.org/en/v1.0.0/#specification

Trailer conventions: https://git-scm.com/docs/git-interpret-trailers

## Steps

1. Inspect staged changes only:
   - `git diff --staged`
2. Summarize the change intent in 1 short sentence.
3. Choose type and optional scope:
   - Types: `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`
4. Determine if this is a breaking change:
   - Use `!` in the header or add a `BREAKING CHANGE:` footer.
5. Output the final commit message wrapped in code fences (```) for easy copying.

## Format

```
type(scope)!: short summary (<= 50 chars)

Body must be present and follow Conventional Commits:
- Explain the motivation and scope (wrap at 72 chars).
- Use complete sentences, no bullet lists unless needed.

BREAKING CHANGE: explanation (if applicable)

Trailer-Key: trailer value
Co-authored-by: Name <email@example.com>
```

## Trailer rules

- Use trailers only when needed.
- Format: `Token: Value` (capitalized token, single space after colon).
- Place trailers after a blank line at the end of the message.
- Include a blank line between the header and body.
- Common trailers: `BREAKING CHANGE`, `Co-authored-by`, `Refs`, `Signed-off-by`.

## Line length

- Keep the header line at 50 characters or fewer.
- Wrap body and trailer lines to 72 characters or fewer.

## Example

```
feat(client): add ct search endpoint

Add certificate transparency search functionality to the client
API. This enables users to search CT logs using regex patterns
and retrieve certificate details.
```
