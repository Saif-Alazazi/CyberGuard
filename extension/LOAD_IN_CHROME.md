# CyberGuard Chrome extension — load it in 3 clicks

A tiny proof-of-concept. It sends the page you're on to the **live CyberGuard engine**
(https://cyberguard-m7tq.onrender.com) and shows the red/green verdict right in the toolbar.
All the detection happens server-side — this is just a thin front door.

## Load it (one time, ~30 seconds)
1. Open Chrome and go to **`chrome://extensions`**
2. Turn on **Developer mode** (top-right toggle)
3. Click **Load unpacked** → pick this `extension` folder
   (`C:\Users\Sa940\Documents\CyberGuard\extension`)

The CyberGuard shield appears in your toolbar. Pin it (puzzle-piece icon → pin) so it's always visible.

## Use it in the demo
- Open any page, then **click the CyberGuard icon**.
- The popup grabs the current URL, checks it, and shows:
  **tier (red/orange/green) · risk score · which UAE brand it fakes · the reasons · a Case ID.**
- **Re-check** button re-runs it (handy if the site was still waking up).

## Demo tips
- **Warm the engine first**: open https://cyberguard-m7tq.onrender.com once, ~20 s before you present,
  so the first check is instant.
- Good things to click it on:
  - a **real** site (e.g. your bank) → green **Official domain**.
  - a scam-pattern URL you've pre-tested → red/orange with reasons.
- If the first click says "waking up", wait ~20 s and hit **Re-check**.

## The line for the judges
> "Same engine as the website — I've just wrapped it as a browser extension too.
> One API, many front doors. Extensions are desktop-only, which is exactly why we led with
> Safe Links for phones, where the scams actually land."

## What it is / isn't
- **Is:** a working demo on a laptop (Chrome, Developer mode).
- **Isn't:** a Chrome Web Store product, and it does **not** run on phones (no browser extensions on mobile).
  Say the words "proof-of-concept" and that's a strength, not a gap.
