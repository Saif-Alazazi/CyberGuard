# CyberGuard extension — load it on a laptop (for the demo today)

This is the local way to run it **right now**, before it's approved on the Chrome Web Store.
(For publishing to the store, see `STORE_LISTING.md`.)

## Load it (one time, ~30 seconds)
1. Open Chrome → address bar → **`chrome://extensions`**
2. Turn on **Developer mode** (top-right toggle)
3. Click **Load unpacked** → pick this `extension` folder
   (`C:\Users\Sa940\Documents\CyberGuard\extension`)
4. Pin it: click the puzzle-piece icon in the toolbar → pin **CyberGuard**.

> Loading the *folder* here is correct. The **ZIP** (`cyberguard-extension.zip`) is only for
> uploading to the Chrome Web Store — don't use it for Load unpacked.

## What it does (two modes)
Click the shield icon to open the popup:
- **Check a message** (main feature): paste a suspicious SMS / WhatsApp / email. It finds every
  link in the text and scores each one — tier, score, which UAE brand it fakes, and the reasons.
- **This page**: one click checks the website you're currently on.
- **AR / EN** button (top-right): switches results between Arabic and English.

## Demo tips
- **Warm the engine first:** open https://cyberguard-m7tq.onrender.com ~20 s before you present.
- Great message to paste live:
  `Your DHL parcel is on hold. A customs fee of AED 2.50 is required: http://b-dhl.top/pay`
  → red **High-risk scam**, "Pretends to be DHL", with reasons.
- Then switch to **AR** to show the bilingual output.
- If the first check says "waking up", wait ~20 s and press the button again.

## The line for the judges
> "Same engine as the website, wrapped as a browser extension. Its main job is the one that matters
> in the UAE — you paste the scam text you received and it tells you, in Arabic or English, exactly
> why it's dangerous. One API, many front doors."
