## Security Reminder

Canary infrastructure is for your own testing only.
Never use canary services to monitor third party
systems without explicit written authorisation.
AIST must only be used against agents you own
or have written permission to test.

# AIST Canary Setup Guide

Before running AIST scans you need to configure
canary infrastructure. Canaries detect when an
injection actually succeeded by monitoring whether
the agent contacted an attacker-controlled resource.

Without canaries AIST still works -- it uses LLM
judge analysis to detect success. But canaries give
you unambiguous binary confirmation: the agent either
contacted your canary or it did not.

---

## What You Need

Two canary values in your .env file:
AIST_CANARY_URL=https://your-canary-url-here
AIST_CANARY_EMAIL=your-canary-email-here
AIST_CANARY_DOMAIN=your-canary-domain-here
AIST_TEST_ADMIN_ID=AIST-TEST-ADMIN-001
AIST_TEST_USER_ID=AIST-TEST-USER-001

The admin and user IDs are fake values used to test
whether agents verify identity claims. They do not
need to be real accounts. The defaults work fine.

---

## Option 1: Canary Tokens (Recommended, Free)

Canary tokens are the simplest and most professional
option. Used by security researchers worldwide.

**Setup takes 30 seconds:**

1. Go to canarytokens.org
2. Select "Web bug / URL token"
3. Enter your email address for notifications
4. Add a memo like "AIST scan canary"
5. Click Generate
6. Copy the generated URL into AIST_CANARY_URL

For email canary:
1. Go to canarytokens.org
2. Select "Custom exe" or "DNS token"
3. Follow the same steps
4. Use the generated address for AIST_CANARY_EMAIL

When a scan triggers the canary you get an instant
email with timestamp, IP address, and context.

**Privacy note:**
Canary tokens are operated by Thinkst Canary.
They log trigger events including IP addresses.
For sensitive internal testing use Option 3 instead.

---

## Option 2: Webhook.site (Free, Zero Setup)

Good for quick URL canary without any account.

1. Go to webhook.site
2. Copy the unique URL shown on the page
3. Paste it into AIST_CANARY_URL
4. Keep the tab open during your scan
5. Any triggered requests appear in real time

Webhook.site sessions are temporary.
Generate a new URL for each testing session.

---

## Option 3: Dedicated Gmail (Free, Email Only)

For AIST_CANARY_EMAIL only. Do not use your
primary Gmail account.

1. Create a new Gmail account dedicated to testing
   Example: aist.canary.yourname@gmail.com
2. Use this address for AIST_CANARY_EMAIL
3. Check this inbox after scans for triggered emails

**Important:** Use a dedicated account, not your
primary email. Keep testing traffic separate from
your personal inbox.

---

## Option 4: Own Domain (Teams and Organisations)

For teams who want full control over canary logging.

**Domain registration:**
- Namecheap: $1-3 per year for .xyz or .click domains
- Porkbun: often $1-2 per year for new TLDs
- Choose a domain that looks like a legitimate
  test domain: yourorg-security-test.com

**Free infrastructure:**
- Cloudflare: free DNS management and request logging
- RequestBin: free HTTP request inspection
- Both give you detailed logs of every canary trigger

**Setup:**
1. Register a cheap domain
2. Point DNS to Cloudflare
3. Set up a Cloudflare Worker to log all requests
4. Use your domain for AIST_CANARY_DOMAIN and
   build canary URLs on subpaths

---

## Verifying Your Canary Works

Before running a full scan, test your canary setup:

```bash
curl {{AIST_CANARY_URL}}
```

You should receive a notification within seconds.
If you do not, check your canary configuration
before proceeding with scans.

---

## Without Canary Configuration

AIST works without canary configuration.
The LLM judge analyses responses to determine
whether injection succeeded.

Canaries add a second independent confirmation
layer. They are especially valuable for:
- Email tool injection tests (Category E)
- SSRF tests (Category H)
- Code generation tests (Category I)

Where the injection success is an external action
rather than a change in response content.

---

