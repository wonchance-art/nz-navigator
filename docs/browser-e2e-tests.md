# Browser E2E gate

`scripts/verify_browser_e2e.mjs` opens the four published editions in a real
Chrome/Chromium engine. It complements the pure diagnosis and calculator
verifiers: those check extracted functions, while this gate checks the actual
DOM, event wiring, rendered output, accessibility state, and mobile layout.
It uses Node.js built-ins only.

## Trust boundary

The runner accepts no JavaScript, CSS selector, expression, or expected text
from the fixture registry. All selectors, input enums, expected output, browser
paths, and the live URL are reviewed constants in the script. The registry is
only this exact versioned enum list:

```json
{
  "schemaVersion": 1,
  "suites": {
    "tabs": ["nz", "ja", "ca", "au"],
    "diagnosis": [
      "nz-student",
      "ja-student",
      "nz-none",
      "ja-none",
      "ca-cec",
      "ca-work",
      "au-sid"
    ],
    "calculators": [
      "nz-netpay",
      "ca-netpay-on",
      "ca-crs",
      "au-netpay-whm",
      "au-netpay-resident"
    ],
    "verification": ["trust-v8"]
  }
}
```

Unknown, duplicate, missing, or extra entries fail. The production fixture is
`tests/fixtures/browser-e2e-cases.json`.

Browser discovery is restricted to these installed binaries:

- macOS Google Chrome and Chromium application paths;
- `/usr/bin/google-chrome`;
- `/usr/bin/google-chrome-stable`;
- `/usr/bin/chromium`;
- `/usr/bin/chromium-browser`.

An explicit `--browser` value must also be one of those paths. Browser absence,
launch failure, DevTools connection failure, crash, timeout, JavaScript
exception, and `console.error`/failed assertion all fail closed.

## Execution model

For a checkout run, Node serves the repository from an ephemeral
`127.0.0.1` port with `Cache-Control: no-store`. The server permits only
`GET` and `HEAD`, resolves real paths beneath the selected root, and does not
proxy traffic. Chrome starts with an ephemeral profile, an incognito browser
context, background networking disabled, and a random loopback DevTools port.

The bounded CDP client calls only reviewed protocol methods. It performs
pointer clicks with `Input.dispatchMouseEvent`; form values dispatch real
`input` and `change` events. Page-level `fetch` and CDP Fetch interception
allow only the tested base origin. Thus a pull-request run cannot fetch remote
application data even if page code changes. Live mode permits only the exact
reviewed Pages origin.

The browser socket, browser process, temporary profile, and local server are
cleaned in a `finally` path. Cleanup continues through all resources even if
one cleanup operation fails.

## Reviewed assertions

Every edition clicks `home`, `diagnose`, `jobs`, `settle`, `scenarios`, and
`snapshot`. After each of the 24 clicks the gate requires:

- exactly six reviewed tab buttons and six top-level panels;
- exactly one active button and active panel;
- the matching URL hash;
- a visible, nonempty active panel;
- `hidden`, `aria-hidden="true"`, and computed `display:none` on all other
  panels;
- the reviewed edition title and ordered tab labels, including the Japanese
  labels;
- `window.innerWidth === 375` and `document.documentElement.scrollWidth <=
  375` at a 375×812 emulated viewport.

Diagnosis cases use the live form controls and submit button. They assert the
runtime recommendation identifier, rendered title, timeline structure and
reviewed stages, money-plan table, entry adjustment, and NZ/JA parity:

- NZ/JA student entry and undecided entry;
- Canada IEC/CEC and Work Permit/PNP separation;
- Australia Work/SID with the 189 alternative.

Calculator cases open their real disclosure widgets and dispatch form events:

- NZ 72,800 → 57,466;
- Canada Ontario 60,000 → 47,340;
- Canada CRS → core 305;
- Australia WHM 52,115 → 43,231;
- Australia resident 60,000 → 50,380.

`verification.html` must fetch and render
`52 / 43 / 136 / 52 / 52 / 0` for source attestations, claims, reviewed
leaves, live-capable, live-extractable, and fixture-only. It must also contain
exactly one visible v8 history entry.

Failures use:

```text
ERROR edition=<edition> fixture=<fixture> step=<step> actual=<...> expected=<...> Fix: <action>
```

## Commands

Run the deterministic unit and mutation suite:

```sh
node --test tests/test_verify_browser_e2e.mjs
```

Run the checkout E2E gate:

```sh
node scripts/verify_browser_e2e.mjs
```

Override the reviewed browser path or bounded command timeout:

```sh
node scripts/verify_browser_e2e.mjs \
  --browser /usr/bin/google-chrome \
  --timeout-ms 15000
```

Run a deliberate Pages smoke test:

```sh
node scripts/verify_browser_e2e.mjs \
  --base-url https://wonchance-art.github.io/nz-navigator/
```

No other external URL is accepted. The pull-request workflow never supplies
`--base-url`; it always runs against the checked-out files and loopback server.

## CI and limitations

The independent `browser-e2e` job in `verify-claims.yml` uses the
Chrome/Chromium already installed on the Ubuntu runner. It runs the mutation
suite first and the real browser gate second. It does not install npm packages
or contact the live site.

This is a reviewed mobile Chromium gate, not a cross-browser matrix. It does
not claim Safari/Firefox rendering parity, visual pixel equivalence, screen
reader behavior, or remote service availability. It intentionally checks a
small set of high-signal diagnosis and calculator cases; the pure v2
regression suites retain broader function-level coverage.
