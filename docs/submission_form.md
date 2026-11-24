# Podium+ submission text

**Project Title:** CyberGuard - UAE scam-link intelligence

**Brief Description** (under 600 characters):

CyberGuard checks a link or a whole SMS/WhatsApp message for UAE-targeted scams. It unrolls redirects and shorteners, checks the final domain against 47 verified UAE bank and government entities, detects look-alikes (English, Arabic, Unicode confusables), queries threat feeds and domain age, and returns a 0-100 risk score with reasons in English and Arabic. It exports police evidence (PDF, JSON, STIX 2.1), flags newly registered UAE look-alike domains, and links scam domains into campaigns.

**Tools Used:** Python, FastAPI, httpx, dnspython, tldextract, rapidfuzz, networkx, reportlab, arabic-reshaper, python-bidi, mmh3, phonenumbers, vis-network, Cloudflare URL Scanner API, Cloudflare DNS over HTTPS, Google Gemini API (gemini-4-hydrogen), OpenPhish, URLhaus, RDAP, aeDA WHOIS, IPinfo Lite, crt.sh, WhoisDS, SerpApi, Tranco, Render

**Repository URL:** https://github.com/Saif-Alazazi/CyberGuard (branch `master`)

**Live URL:** https://cyberguard-m7tq.onrender.com

**Presentation:** docs/CyberGuard_Presentation.pptx (PDF: docs/CyberGuard_Presentation.pdf)

**Project description:** docs/CyberGuard_Project_Description.pdf
