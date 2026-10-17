# Launch checklist

ScamShield must not be launched publicly until every item in section 1 is done. Section 2 records the design rules the site is held to; they are enforced by `tests/test_web_standards.py`, so a change that breaks one fails the test run.

Status on 17 October 2026: **not launched.** The app runs on an IBM LinuxONE Community Cloud VM and is reached through an SSH tunnel for the datathon demo. No public address exists.

## 1. Required before any public launch

| Item | Status | Notes |
|---|---|---|
| Custom domain connected | **Not done** | Needs a domain the team owns, DNS records and a publicly reachable server. The Community Cloud VM is a shared, free environment; check its terms before exposing a public port. |
| HTTPS with a valid certificate | **Not done** | Needed once a domain exists (for example a reverse proxy with a free Let's Encrypt certificate). The privacy page already tells users to check for https. |
| Production web server | **Not done** | The app currently runs on Flask's built-in server, which is for development. Use a production server (for example gunicorn) behind the proxy. |
| Favicon | Done | `web/favicon.svg`, `favicon.ico`, `apple-touch-icon.png`, linked from every page. |
| "Made with AI" or similar tag removed | Done | None exists. The test suite fails if a badge phrase appears on any page. |
| Privacy policy page | Done | `/privacy`. Written from the code's actual behaviour. Needs legal review before launch. |
| Terms and conditions page | Done | `/terms`. Needs legal review before launch. |
| Operator identity and jurisdiction in the legal pages | **Not done** | The pages name "the project team" and give a GitHub issues link as the contact. A public service should state who operates it, give a monitored contact address, and name the governing law. |
| Log retention period | **Not done** | The privacy page says logs have no automatic deletion. Decide a retention period and implement it. |

## 2. Design rules, and how they are met

| Rule | How it is met |
|---|---|
| No emoji or emoji icons | None in any page, script or style sheet; checked by test. |
| No em-dashes | None in site copy; checked by test. |
| No purple gradients or any gradients | Flat colours only; single blue accent (IBM Carbon Blue 60); checked by test. |
| No over-the-top animation, no cursor effects | No animations, transitions, smooth scrolling or cursor scripts; checked by test. |
| No fake buttons | Every button performs a real action (check, clear, read aloud, feedback). The example picker loads real demo messages. |
| No fake reviews, testimonials or metrics | The site shows none. The only figures are measured results with their date, test sizes and limits, on the How it works page. |
| No fake hero text | The headline and sentence under it state exactly what the tool does. |
| No stock or AI-generated photos | The site uses no photographs or illustrations. The logo is a plain geometric mark. |
| No marketing filler copy | Buzzwords are banned by test; copy is plain and specific. |
| No third-party requests | The IBM Plex typeface is served from the same server; the test run records zero outside requests. |

## 3. Design references

- IBM Carbon Design System (colour tokens, flat panels, square controls, accessible contrast): https://carbondesignsystem.com
- GOV.UK Design System (plain-language content, restrained banners, accessibility first): https://design-system.service.gov.uk
- IBM Plex typeface, SIL Open Font Licence: https://github.com/IBM/plex
