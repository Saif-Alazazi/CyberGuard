# CyberGuard — Chrome Web Store submission kit

Everything below is copy-paste ready for the Developer Dashboard. Fields are grouped by the
dashboard tab they belong to.

---

## 0) Before you upload
- The ZIP to upload is **`cyberguard-extension.zip`** (in this folder). It contains only the
  extension files (manifest, popup, icons) — not the docs.
- **Timing:** new extensions are **reviewed by Google first** (usually hours, sometimes a few
  days). It will **not** be public instantly. For a live demo today, keep using **Load unpacked**.
- **Privacy policy URL** (required, already hosted on your site once you redeploy):
  `https://cyberguard-m7tq.onrender.com/static/privacy.html`
  → Open it once after deploying and **add a contact email** where the page says to
  (use a dedicated address, not your personal Gmail).

---

## 1) Store listing tab

**Name** (shown on the store)
```
CyberGuard UAE — Scam Message & Link Checker
```

**Summary** (short description, max 132 chars)
```
Paste a suspicious SMS or WhatsApp message, or check the page you're on — instant scam verdict with reasons in English & Arabic.
```

**Description** (detailed)
```
CyberGuard tells you in about one second whether a link or a message is a scam — and explains why, in English and Arabic.

HOW TO USE IT
• Check a message: paste a suspicious SMS, WhatsApp or email message. CyberGuard finds every link inside it and scores each one.
• This page: one click checks the website you're currently on.

WHAT YOU GET
• A clear red / orange / green verdict and a risk score.
• The reason it's flagged — e.g. it imitates a known UAE brand on a web address that brand doesn't own.
• The specific brand being faked (banks, Etisalat/e&, DEWA, Salik, RTA, UAE PASS, parcels, and more).
• Bilingual results — switch between English and Arabic with one tap.

WHY IT'S DIFFERENT
UAE scams arrive mostly as text messages — fake fines, parcels, bank alerts. CyberGuard is built for exactly that: it reads the whole message, not just one link, and it recognises the local brands scammers impersonate. It does not simply block "unknown" sites; it explains its reasoning so you can decide.

PRIVACY
CyberGuard only receives the link or message you choose to check, uses it only to score it, and never sells your data or uses it for advertising. It does not read your pages, history or tabs in the background. See the privacy policy for details.

Built for the ScamShield AI Hackathon (42 Abu Dhabi × Abu Dhabi Police).
```

**Category:** `Tools` (alternative: `Productivity`)

**Language:** `English` (you can add `Arabic` as an additional language)

**Screenshots:** use the images in `store_assets/` (1280×800). At least one is required.

**Store icon:** `icons/icon128.png` (already in the package).

---

## 2) Privacy practices tab

**Single purpose** (one sentence)
```
CyberGuard checks whether a message or web link is a scam and explains why.
```

**Permission justifications**

- `activeTab`
```
Used only when the user clicks "This page". It reads the current tab's web address at that moment so the address can be checked for scams. The extension does not access tabs in the background.
```

- Host permission `https://cyberguard-m7tq.onrender.com/*`
```
This is CyberGuard's own detection service. The link or message text the user chooses to check is sent to this address to be analysed and scored. No other site is contacted.
```

- Remote code: **No**, the extension does not use remote code. All code is in the package.

**Data usage — declare these data types as collected:**
- **Website content** — the URLs / page address the user submits to be checked.
- **Personal communications** — because users may paste SMS / WhatsApp / email **message text** into
  the "Check a message" box. (Declare this honestly; it's the message content you analyse.)

> Do NOT declare: name, address, email, phone, financial info, health, location, authentication
> info, personal/web history, or user activity — the extension collects none of those.

**Required certifications (all true — you can check all three):**
- ✅ I do not sell or transfer user data to third parties, outside the approved use cases.
- ✅ I do not use or transfer user data for purposes unrelated to the item's single purpose.
- ✅ I do not use or transfer user data to determine creditworthiness or for lending purposes.

**Privacy policy URL**
```
https://cyberguard-m7tq.onrender.com/static/privacy.html
```

---

## 3) Distribution
- **Visibility:** Public (or "Unlisted" if you only want people with the link to install it —
  good for a controlled demo while you finish).
- **Regions:** All regions (or United Arab Emirates only, your choice).
- **Pricing:** Free.

---

## 4) After you submit
- Status shows "Pending review". You'll get an email when it's approved or if they need a change.
- If they ask for anything, it's almost always the **privacy policy** or a **permission
  justification** — both are already written above.
