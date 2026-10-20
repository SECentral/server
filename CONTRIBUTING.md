# Contributing

Feedback, bug reports, documentation improvements, and pull requests are welcome.
For larger changes, open an issue first to discuss the approach.

## Development

Start with [README.md](README.md) and follow [TEST.md](TEST.md) for
development setup and checks. Run Ruby and Rails tooling inside Podman
containers, as described there.

Follow existing Rails and frontend patterns. Preserve original event
evidence and keep security-impacting recommendations explicit. Changes to
the ingestion protocol must consider compatibility and be documented.

## Pull requests

- Keep changes focused and follow the existing code style.
- Add or update tests for behavior changes.
- Run the checks described in TEST.md that apply to your changes.
- Describe the problem, your changes, and how you tested them.

Remove credentials and sensitive host information from reports and examples.
