# Branding

`secentral-logo.svg` is the dot-free SECentral shield and wordmark shared with
the project website. Marcellus lettering has been converted to vector paths;
no font or external resources are loaded by the logo.

The source font is Marcellus Regular by Astigmatic, distributed by Google Fonts
under the SIL Open Font License (retained in `OFL.txt`).

The teal SVG is used directly on light surfaces. In dark mode, the existing
`.pf-v6-theme-dark` selector renders the same asset white using a CSS filter.
This follows the application's theme rather than the operating system's theme.
The shield favicons are in `frontend/public/` and work on light and dark tabs.
