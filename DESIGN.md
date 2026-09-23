---
name: NekoCTI
description: A personal threat-intel monitor styled as a wrist-worn status device, checked routinely rather than browsed once.
colors:
  phosphor-green: "#14fe17"
  olive-black: "#272b23"
  green-wash: "rgba(20, 254, 23, 0.12)"
  amber: "#ffb347"
  signal-red: "#ff5c4d"
typography:
  label:
    fontFamily: "'PipBoy' (Monofonto), 'Courier New', monospace"
    fontSize: "26px"
    fontWeight: 400
    lineHeight: 1
    letterSpacing: "1px"
  body:
    fontFamily: "'PipBoy' (Monofonto), 'Courier New', monospace"
    fontSize: "17px"
    fontWeight: 400
    lineHeight: 1.4
    letterSpacing: "normal"
  mono-small:
    fontFamily: "'PipBoy' (Monofonto), 'Courier New', monospace"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.3
    letterSpacing: "1px"
  title:
    fontFamily: "'PipBoy' (Monofonto), 'Courier New', monospace"
    fontSize: "22px"
    fontWeight: 400
    lineHeight: 1.3
    letterSpacing: "1px"
  title-compact:
    fontFamily: "'PipBoy' (Monofonto), 'Courier New', monospace"
    fontSize: "18px"
    fontWeight: 400
    lineHeight: 1.3
    letterSpacing: "1px"
  body-compact:
    fontFamily: "'PipBoy' (Monofonto), 'Courier New', monospace"
    fontSize: "16px"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "normal"
  meta:
    fontFamily: "'PipBoy' (Monofonto), 'Courier New', monospace"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.3
    letterSpacing: "1px"
  micro:
    fontFamily: "'PipBoy' (Monofonto), 'Courier New', monospace"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: 1.2
    letterSpacing: "3px"
  fine-print:
    fontFamily: "'PipBoy' (Monofonto), 'Courier New', monospace"
    fontSize: "11px"
    fontWeight: 400
    lineHeight: 1.6
    letterSpacing: "0.05em"
rounded:
  none: "0px"
  hair: "2px"
  device: "28px"
  device-compact: "16px"
  screen: "10px"
  screen-compact: "6px"
spacing:
  xs: "6px"
  sm: "10px"
  md: "18px"
  lg: "24px"
  xl: "40px"
components:
  tab:
    textColor: "{colors.phosphor-green}"
    typography: "{typography.label}"
    padding: "0 0 6px"
  tab-active:
    textColor: "{colors.phosphor-green}"
    typography: "{typography.label}"
  row:
    backgroundColor: "transparent"
    textColor: "{colors.phosphor-green}"
    typography: "{typography.body}"
    rounded: "{rounded.hair}"
    padding: "9px 14px 9px 26px"
  row-hover:
    backgroundColor: "{colors.green-wash}"
    textColor: "{colors.phosphor-green}"
  row-selected:
    backgroundColor: "{colors.phosphor-green}"
    textColor: "{colors.olive-black}"
  panel-input:
    backgroundColor: "transparent"
    textColor: "{colors.phosphor-green}"
    typography: "{typography.mono-small}"
    padding: "6px 10px"
  panel-button:
    backgroundColor: "transparent"
    textColor: "{colors.phosphor-green}"
    typography: "{typography.mono-small}"
    padding: "6px 14px"
  panel-button-hover:
    backgroundColor: "{colors.phosphor-green}"
    textColor: "{colors.olive-black}"
---

# Design System: NekoCTI

## Overview

**Creative North Star: "The Pip-Boy Personal Monitor"**

NekoCTI reads as a wrist-worn status device retrofitted for threat intel: a single phosphor-green screen inside a dark device bezel, checked in on routinely rather than opened as a dashboard destination. The direction was pinned by the user ("fallout themed, keeping to darker side of things") and then verified against a real Fallout 4 Pip-Boy CSS recreation (`AviralMehrotra/Fallout4-Pip-Boy`) rather than built from memory, which corrected several assumptions before any code shipped: a horizontal top tab bar rather than a vertical rail, opacity-dimming for tab state rather than color inversion, flat rows with a small square bullet marker rather than boxed ASCII-corner cards, and the real muted `#14fe17` on `#272b23` pair rather than a near-black background. The build stayed inside that verified world through two finish-review rounds and a confirmed ship, including a mobile treatment and a fifth tab (Campaigns) built after the comp, both extending the same grammar rather than introducing a new one.

The system is confirmed flat, monospaced, and low-chroma: one accent color carries all interaction and selection state, everything else is olive-black, dimmed green, or the two status colors (amber, signal-red). Density is high and unpadded-feeling by device standards - this is a monitoring instrument, not an editorial surface - but every list, panel, and overlay scrolls independently rather than the page as a whole, keeping the top nav and bottom footer always in view.

**Key Characteristics:**
- Single-accent phosphor green on olive-black, never a second competing hue for anything but status (amber/red).
- Selection state is inversion, not addition: the accent becomes the background, olive-black becomes the text.
- Horizontal, opacity-dimmed tabs instead of a sidebar; a persistent bottom status footer instead of a top-of-page summary.
- Everything is monospaced, uppercase-leaning for labels, and framed by hairline or 1-2px borders - no shadows, no gradients except the device bezel itself.
- A permanent scanline overlay and CRT-style device frame carry the "monitor" reading even in flat, borderless list content.

## Colors

The palette is a single accent against a dark neutral, plus two status colors reserved for meaning, never decoration.

### Primary
- **Phosphor Green** (`#14fe17`): the only accent in the system. Used for all text, borders, active/hover/selected states, focus rings, the scrollbar thumb, and selection highlight (`::selection`). Its exact value and the olive-black pairing came from the verified Fallout 4 reference, not an invented "terminal green."

### Neutral
- **Olive-Black** (`#272b23`): the screen background. Confirmed a "muted dark olive," not near-black - a real correction made against the reference build before this shipped.
- **Green Wash** (`rgba(20, 254, 23, 0.12)`): the low-opacity tint used for row hover and the footer's status chip background - depth without a second color.
- **Device Frame** (`linear-gradient(160deg, #1a1d16 0%, #0d0f0b 100%)` on `#000` page background): the bezel around the screen; the only place a gradient or shadow appears in the whole system.

### Status
- **Amber** (`#ffb347`): reserved, defined at the token level, used sparingly for secondary status signaling.
- **Signal Red** (`#ff5c4d`): critical/error signal - CVSS-critical values in list rows, and every fetch-failure error state across the app.

### Named Rules
**The One Accent Rule.** Phosphor green is the only interactive/brand color in the system. Nothing else earns a hover, focus, or selected treatment in a second hue - amber and red are status-only and never used for navigation or emphasis.

**The Inversion Rule.** Selection and "on" states never add a highlight color on top of content; they invert foreground and background (green fill, olive-black text). This is the one state-change grammar used everywhere: rows, active list markers, panel buttons on hover.

## Typography

**Display/Body/Label Font:** "PipBoy" (Monofonto), falling back to `'Courier New', monospace`.

**Character:** One monospaced face carries every role in the system - there is no separate display or body pairing. Hierarchy comes from size, opacity, and letter-spacing, not a font change, which reads as instrument-panel readout rather than editorial typography.

### Hierarchy
- **Tab label** (400, 26px, tight line-height, 1px letter-spacing): the top nav's primary wayfinding; inactive tabs sit at 0.5 opacity, active at full opacity with a faint text-shadow.
- **Reader title** (400, 22px desktop / 18px mobile, 1.3 line-height): the article/technique/campaign/entity title inside the full-content overlay.
- **Row body** (400, 17px): list row titles and inline content - the dominant reading size across High Ticket, Watchlist, Breaches, Entities, Campaigns, and Archive.
- **Meta/label** (400, 13-15px, 1-3px letter-spacing, frequently uppercase): section labels (`LOADING...`, `// TRACKED CAMPAIGNS`), sub-tabs, row meta (dates, CVE IDs), panel category labels, footer chips.

### Named Rules
**The One Face Rule.** Every piece of text in the system, from tab labels to article body copy, is the same monospaced family. No secondary serif/sans is introduced anywhere, including the in-dashboard reader - readability inside the article overlay is handled with line-height and max-width, not a font swap.

## Layout

The screen is a fixed-height flex column that never scrolls as a page: `topnav` -> `subnav` -> one primary content region (`list`, `panel`, or `attack-view`, toggled via `hidden`) -> a persistent `footer`. Only the content region scrolls internally (`overflow-y: auto`), so the tab bar and status footer stay pinned regardless of list length. The device itself is a fixed-margin bezel (14px desktop) around a full-viewport screen, replacing an earlier fixed-pixel device frame after real usage showed it wasted space on wide monitors.

List content uses a tight vertical rhythm: rows at ~9px vertical padding with a 3px gap between them, grouped under uppercase section labels. The ATT&CK matrix is the one grid layout in the system - fixed 210px columns (one per tactic) in a horizontally scrolling flex row, with sticky column headers.

**Phone and tablet (rebuilt 23 September 2026, Neko's direction).** The earlier single 640px breakpoint let the eight tabs wrap onto five lines: on a 390x664 phone the chrome took 79% of the screen and one article was visible, and the reader's leftover 500px minimum width pushed article text and the CLOSE button off the right edge. Two breakpoints now:

- **1023px and below (phone and tablet):** the tab row is hidden and replaced by the **mobile bar** (wordmark, current section and its count, a menu button) and the **section menu** (see Components). Range sub-tabs become a 44px segmented control that inverts for the active range; search folds into an icon that takes the row over when opened. Rows stack title over meta, and long unbreakable tokens (package paths, version ranges) break anywhere rather than overrunning. The footer becomes one line: status, time since the last check, RUN CHECK; the archive/high-ticket chips move into the menu, and the full freshness line opens on tapping the status, with a signal-red square marking an awaiting-severity backlog while it is folded. The reader keeps text and images side by side at roughly 60/40 (Neko's call for tablets). The bezel keeps its 16px compact radius with no outer margin. Every tappable element is at least 44px, and every input is 16px so the browser never zooms on focus.
- **599px and below (phone):** the bezel gives way to the phone's own edges, with safe-area insets respected; article images stack after the text (Neko's call); the reader title drops to the compact size. 599px rather than 640px because the household is Samsung: a Galaxy Tab S9 is exactly 640px wide in portrait and must get the tablet layout, while Galaxy phones run 360 to 480px.

Verified on emulated Galaxy S24, A55, S9+ (320px), Tab S9, Tab S4 and S24 landscape, plus a 1440px desktop regression check: the content region went from 21% to 72-83% of a portrait phone's height, nothing overruns the screen edge, and desktop is unchanged. Known limit: a phone held sideways leaves the content about 45% of a 360px-high screen, one row.

### Named Rules
**The Pinned Frame Rule.** Navigation (top) and status (bottom) never scroll away, at any viewport width. Only the named content region between them scrolls.

**The Touch Floor Rule.** Below 1024px, nothing tappable is smaller than 44px in either dimension, and no text input is smaller than 16px.

## Elevation & Depth

The system is flat by design: no drop shadows or elevation levels on any interactive surface. The single exception is the device bezel itself (`box-shadow: 0 40px 80px rgba(0,0,0,0.6), inset 0 0 0 2px #34382c`), which exists to sell the "physical device" framing, not to layer UI content. Inside the screen, depth is conveyed entirely through opacity (dimmed vs. full-strength tabs and matrix cells) and the green-wash tint for hover, never through shadow or z-axis stacking except where an overlay (the reader, matched by the ATT&CK/manage panels) needs to sit above the base list via `z-index`.

### Named Rules
**The Flat Screen Rule.** Nothing inside `.screen` casts a shadow. Depth and state are shown by opacity and background-tint changes only; the bezel's shadow is the one and only elevation cue in the system, and it belongs to the device frame, not to content.

## Shapes

Corners are close to square throughout: rows and inputs use a 2px hairline radius, the screen uses 10px (6px on mobile), and only the outermost device bezel gets a real radius (28px, 16px on mobile) to read as rounded hardware. Borders are 1-2px solid phosphor green at low or full opacity depending on state - term chips, entity cards, inputs, and buttons all share this same thin-outline treatment rather than filled backgrounds. The permanent scanline overlay (`repeating-linear-gradient`, 2px pitch, 0.3 opacity) is a fixed textural layer across the entire screen, not a per-component effect.

## Components

### Navigation (Top Tabs + Sub-tabs)
- **Style:** horizontal row, baseline-aligned, wordmark pinned left/absolute. Six primary tabs (High Ticket, Watchlist, Breaches, APT/Entities, Campaigns, Archive) plus a standalone ATT&CK tab, each with a live count badge.
- **Default/active:** inactive tabs sit at 0.5 opacity; the active tab is full opacity with a subtle green text-shadow and its underline broken by a background-colored gap over the shared bottom border.
- **Sub-nav:** a secondary row directly beneath (time-range sub-tabs: 24H / 7D / All Time) using the same dim/active opacity language at smaller size; a right-aligned "MANAGE WATCHLIST" toggle appears only on tabs that support it.
- **Phone and tablet:** the tab row is hidden (the `.tab` elements stay in the DOM as the single source of truth) and replaced by the mobile bar and section menu below.

### Mobile Bar and Section Menu (phone and tablet)
- **Mobile bar:** one 56px line under the screen top: dim wordmark, the current section at the 22px title size with its live count, and a 44px square menu button. A 2px phosphor rule beneath it echoes the desktop tab row's baseline.
- **Section menu:** a full-screen list inside the screen, rebuilt from the `.tab` elements each time it opens so labels and counts cannot drift. Each section is a row (square bullet, count right-aligned) and the current one is inverted, per the Inversion Rule. Choosing one clicks its tab; the menu closes on selection, the close button, or Escape. Focus moves to the current section on open and back to the button on close.
- **Motion:** the menu's arrival is the system's one authored motion, a 220ms `clip-path` wipe downward from the bar like a screen redraw, removed under `prefers-reduced-motion`.
- **Icons:** drawn SVG, 2.25 stroke, square caps to match the square bullets; never glyph stand-ins. Icon buttons invert when pressed or open.

### Rows (List Items)
- **Shape:** flat, 2px-radius, no border by default.
- **Marker:** every row carries a small square bullet (9x9px) at the left edge - dim green when unselected, olive-black when selected (inverted along with the row).
- **Hover:** unselected rows tint with the green-wash background; selected rows do not restate hover.
- **Selected:** the Inversion Rule - full green background, olive-black text, meta opacity raised to 1, and a CVSS-critical value inside a selected row switches to a dark red-on-green rather than the default bright red-on-dark.
- **Phone and tablet:** title stacks above meta instead of sitting side by side, and the bullet aligns to the first title line.

### Cards (Entity Cards, Term Chips)
- **Corner Style:** square-to-hairline; no fill at rest, thin green border only.
- **Background:** transparent by default; entity cards tint with green-wash on hover, term-chip remove controls invert to green-on-black on hover.
- **Border:** 1px solid phosphor green, always.
- **Internal Padding:** compact (`10px 14px` cards, `4px 10px` chips).

### Inputs / Fields
- **Style:** transparent background, 1px solid phosphor-green border, no radius, monospace text, placeholder at 0.4 opacity.
- **Focus:** the global focus-visible rule (`2px solid #14fe17`, 2px offset) - not a bespoke per-input treatment, applied consistently across search, watchlist/entity/campaign management inputs.
- **Error / Disabled:** no disabled-input state exists in the shipped build; error states live at the list/panel/overlay level (see below), not on individual fields.

### The Reader Overlay (signature component)
Full-screen overlay (`position: absolute; inset: 0`) that opens in place of the list to show a complete article/technique/campaign/entity body inside the device screen itself - confirmed a hard requirement so the dashboard is "the central place for consumption," not a launchpad to the source site. Header carries the title and a bordered close control; a meta strip (source, date, matched terms) sits below a hairline divider; the body scrolls independently at 900px max-width with 1.7 line-height. The original source link is retained but demoted to a small, low-opacity line beneath the body. Uses `:not([hidden])` rather than a bare `display: flex` selector so the browser's own `[hidden]` attribute isn't overridden by equal-specificity CSS - a bug class this build explicitly checked for based on a prior incident elsewhere in this environment.

### The ATT&CK Matrix (signature component)
Tactics as sticky-header columns (fixed 210px width) in a horizontally scrolling row, techniques as cells stacked within each column. Unmatched techniques sit at 0.35 opacity with a dim border and no pointer affordance; techniques with real captured-intel matches light up to full opacity, a solid green border, green-wash fill, and become clickable through to their matched articles, with a bold match count floated in the cell. A live text search dims/hides non-matching cells (`.dimmed-search`) without altering the grid structure.

### Empty / Error States
- **Empty:** centered, 0.6-opacity single-line message per context (e.g. "NO CAMPAIGNS TRACKED YET.").
- **Error:** every fetch call site (list, reader, ATT&CK view, watchlist panel, entities panel, campaigns panel, campaign-article drill-down) renders the same `error-state` treatment on failure - full opacity, signal-red text, "SIGNAL LOST - COULD NOT REACH NEKOCTI BACKEND" plus the real error message. This is a system-wide, single-format rule, not a per-view improvisation: it was added uniformly across every fetch site in the same finish-review fix pass.

## Do's and Don'ts

### Do:
- **Do** keep phosphor green (`#14fe17`) as the only interactive/brand hue; amber and signal-red are status-only.
- **Do** express selection and "on" state as full inversion (green background, olive-black text), never as an added highlight color or border glow on top of the existing surface.
- **Do** route every new fetch-backed view through the same `error-state` (signal-red, "SIGNAL LOST...") and empty-state (dim, centered, single line) pattern rather than inventing a new failure treatment per view.
- **Do** keep navigation and the status footer pinned and let only the named content region scroll, at every viewport width.
- **Do** give any new horizontally-constrained row of controls (tabs, filters) its own local `overflow-x: auto` before assuming it needs to wrap or hide items on mobile.

### Don't:
- **Don't** introduce a second accent color for interactive/brand purposes - the system is confirmed single-accent; new status meanings should be justified as carefully as amber/red were, not added freely.
- **Don't** add drop shadows to any surface inside `.screen`. The bezel's shadow is the system's one elevation cue; content surfaces stay flat and use opacity/tint for depth.
- **Don't** introduce a second typeface for emphasis or hierarchy. Every role in this system, including long-form reading in the article overlay, stays on the one monospaced family.
- **Don't** use a bare `display` value to show/hide an overlay or panel that's also toggled via the `hidden` attribute - use `:not([hidden])` to avoid the equal-specificity bug this build explicitly guarded against.
