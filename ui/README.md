# MEGATRON — UI

The design system, and the operator dashboard for the shield tier.

| | |
|---|---|
| [`tokens.css`](tokens.css) | Colour, type and density. The single source of truth for the admin console, the customer portal, and the installer's TUI colour choices. |
| [`shield/index.html`](shield/index.html) | Operator dashboard: what the shield blocked, why, and from where. Client of [`contracts/shield-telemetry.openapi.yaml`](../contracts/shield-telemetry.openapi.yaml). |
| [`validate_palette.py`](validate_palette.py) | The colour checks, runnable. |
| [`test_validate_palette.py`](test_validate_palette.py) | Proof that those checks can fail. |

## Status — what has and has not been verified

Being precise about this matters more here than usual, because a screenshot of
a dashboard is the easiest thing in this project to mistake for a working
product.

**Verified by execution:**

- The palette passes every computable check in both modes — run
  `python ui/validate_palette.py "#2C7CBF,#9A6614" --mode light --surface "#F5F7F7"`.
- Every ink, accent and status token clears its contrast floor against every
  surface it can land on (`python ci/policy_check.py`, rule group PALETTE).
- The dashboard's fixture conforms to the contract it cites, schema by schema
  (`python ci/check_fixtures.py`).
- The page is structurally well-formed, every `getElementById` target exists in
  the markup, and it references no external URL.

**NOT verified:**

- **The JavaScript has never been executed and the page has never been
  rendered.** There is no browser and no Node runtime on the machine this was
  built on. Layout, the SVG charts, the linked crosshair and the theme toggle
  are reasoned about, not observed.
- No MEGATRON node has ever served this page. The Go node agent behind the
  telemetry contract does not exist ([#4](https://github.com/XYZTheo/MEGATRON/issues/4)),
  and no MEGATRON component has run on Linux at all
  ([#2](https://github.com/XYZTheo/MEGATRON/issues/2)).

Opened from the filesystem, the page renders fixture data and says so in a
banner that cannot be dismissed. That banner is not decoration: a dashboard
showing invented numbers must never be mistakable for one showing real ones.

## The rules the design system encodes

**Colour means something.** The chrome is monochrome ink; the only saturated
pixels are traffic, call state and alarms. Decorative colour in a NOC trains
operators to ignore colour, which is the exact reflex you do not want at 3am.
MagnusBilling's ExtJS admin is the thing being answered — everything is chrome
and nothing is signal.

**Absorbed attack traffic is brass, not red.** Absorbed volume is the product
working. Red is reserved for states that need a human.

**Status never rides on colour alone.** Every status ships with a glyph and a
word beside it, so it survives colour-vision deficiency, forced-colors mode and
a printout.

**Every ink step is legible.** All three clear WCAG 4.5:1 against the worst
surface they can land on. "Faint" is carried by size, weight and tracking —
never by dropping below the legible range. The first cut of `tokens.css` got
this wrong (`--mg-ink-faint` at 2.70:1 while carrying the 10px axis labels),
which is why it is now a build failure rather than a matter of taste.

**Two measures at different scales get two charts.** Never two y-axes on one
chart: relative heights there are an artefact of two arbitrary scales, and the
crossing points mean nothing.

## What CI enforces

Colour is treated as a correctness property, not a preference, because the
operator reading this during an attack may well be one of the ~8% of men with a
colour-vision deficiency.

| Rule | Enforces |
|---|---|
| `THEME-SYNC` | The palette is declared three times (plain CSS cannot share it without `light-dark()`). No block may omit a token, the two dark blocks must agree, and every colour must be a parseable 6-digit hex so nothing silently stops being measured. |
| `PALETTE` | Contrast floors, the categorical/colour-vision battery on the chart series, and no series wearing a status colour. Fails closed: deleting `--mg-series-*` is a build failure, not a quiet skip. |
| `UI-SELF-CONTAINED` | No external requests from anything under `ui/`, and no colour literal outside `tokens.css` — a literal is invisible to the checks above. |

```sh
python ci/policy_check.py            # the gate
python ci/test_policy_check.py       # proof the gate can fail
python ui/test_validate_palette.py   # proof the colour checks can fail
python ci/check_fixtures.py          # fixture vs contract (needs pyyaml, jsonschema)
```

## Changing a colour

Do not nudge a hex. Re-run the validator for both modes, and expect CI to
disagree with you if the change is not defensible:

```sh
python ui/validate_palette.py "#2C7CBF,#9A6614" --mode light --surface "#F5F7F7"
python ui/validate_palette.py "#4A98D8,#B87C2A" --mode dark  --surface "#0E1418"
```

Dark is a designed mode, not an inversion — its steps are re-picked from the
same ramps and re-validated against the dark surface. Note that a light palette
validating under `--mode dark` proves nothing: the dark lightness band sits
inside the light one, so that result is arithmetic, not evidence.
