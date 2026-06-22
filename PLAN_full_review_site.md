# Plan: turning the website into a full FS-review tool

## The goal

Right now the website does a *quick* check on an uploaded `.docx` — it detects the
standard statement headings, counts tables, and flags any column that doesn't add up.
You want it to do the *full* review that the FS-review skill does: independently
recalculate every figure, check the statements agree with each other and with the
notes, review FRS 1 / 2 / 12 / 109 / 115 / 116 compliance, check grammar, and produce
a polished Word + PDF report with a `_reviewed` suffix.

This is achievable, but it's a meaningfully bigger system than the uploader we built.
This document explains why, what needs to change, and the cheapest sensible path.

## Why the current free setup can't do it

The deep review isn't really a "calculation" — it's *reasoning*. Deciding whether a
going-concern disclosure is adequate, whether a financial-instruments note wrongly
includes prepayments, or whether "recognized" should be "recognised" can't be hard-coded
for every possible layout of accounts. The skill does this by having an AI (Claude) read
the document and reason about it, while a script independently checks the arithmetic.

That creates two hard requirements the free PythonAnywhere plan can't meet:

1. **The site must reach the internet to call the AI.** Free PythonAnywhere accounts can
   only contact a fixed allow-list of sites; the AI service is not on it. Paid accounts
   have full internet access. (Confirmed on PythonAnywhere's own pages.)
2. **The site must turn the report into a PDF.** LibreOffice — the usual tool for a
   faithful Word→PDF conversion — isn't pre-installed on PythonAnywhere. There are
   work-arounds, but PDF fidelity is the one part that may push us to a different host.

So the upgrade is really three pieces of work: a hosting bump, an AI-powered review
engine, and report generation.

## How the upgraded site would work

When someone uploads a file, the site would:

1. **Extract** every paragraph and table from the `.docx` (we already do this with
   `python-docx`).
2. **Recalculate the numbers in code** — the deterministic tally and balance-equation
   checks, expanded to cover the P&L, balance sheet, changes-in-equity, cash flow, PPE
   note and tax reconciliation. (The skill's own rule: never trust hand/AI math — verify
   with a script.)
3. **Send the document text to the AI** with the skill's review checklist, and get back
   structured findings: cross-statement mismatches, FRS observations, and grammar issues.
4. **Merge** the code's arithmetic findings with the AI's findings.
5. **Generate the report** as a Word document in the skill's house style (dark/light-blue
   headers, red rows for errors, green for verified, Arial, page numbers), then convert it
   to PDF.
6. **Show the report on screen and offer both files for download**, saved with the
   `_reviewed` suffix.

Because steps 3–5 take time (anywhere from ~30 seconds to a few minutes per file), the
upload page would show a "review in progress" status and then reveal the report when it's
done, rather than making you stare at a frozen page. A small background worker handles the
job while the website stays responsive.

## What needs to change, concretely

The login, upload, file list and storage we've already built stay as they are. The new
parts are: the expanded arithmetic checker, the AI call, the report builder (Word + PDF),
and the background-job mechanism. The biggest single decision is the host, because it
determines how cleanly the AI calls, the PDF step, and the background worker can run.

| Option | Cost | Pros | Trade-offs |
|--------|------|------|-----------|
| **A. Upgrade current PythonAnywhere to the "Hacker" plan** | ~US$5/mo | Least disruption — site already lives here; full internet so AI works; supports an always-on background worker | PDF needs a work-around (Abiword or a conversion service); slightly less control |
| **B. Move to a container host (Render / Railway)** | ~US$7/mo | Full control; install LibreOffice for pixel-faithful PDF; clean background workers | A migration; you'd set up a new host (I can drive most of it) |

**Recommendation:** start with **Option A** (cheapest, no migration, and we're already set
up there). If the PDF output isn't faithful enough to the skill's formatting, move the PDF
step — or the whole app — to Option B later.

## Costs and what I'll need from you

- **Hosting:** ~US$5/month (PythonAnywhere Hacker) — required for the AI calls to work.
- **AI usage:** billed per review by the AI provider. A typical 20–40 page set of accounts
  is roughly US$0.10–0.50 per review depending on the model chosen. Low volume = low cost.
- **An AI API key:** you (or AssemblyWorks) would create an Anthropic API key and I'd store
  it on the server as a secret. I can't create the key or enter the card details for you —
  I'll walk you through it, and it takes a few minutes.

## Suggested rollout

1. **Phase 1 — Engine, on screen.** Upgrade the plan, wire up the AI review + the expanded
   arithmetic checker, and show the full findings *on the web page* (sections verified,
   numerical discrepancies, FRS observations, grammar). No PDF yet. This proves the review
   quality end-to-end.
2. **Phase 2 — Polished report.** Generate the Word report in the skill's house style and a
   PDF, both downloadable with the `_reviewed` suffix.
3. **Phase 3 — Niceties.** Per-colleague logins, a history of past reviews, and (optional)
   saving the finished report straight back to the "FS to review" SharePoint folder.

## Decisions I need from you to start

1. Are you OK with **~US$5/month hosting plus small per-review AI costs**? (Without the paid
   plan the site simply can't run the deep review.)
2. **Option A (stay on PythonAnywhere) or B (move to a container host)** for the first build?
3. Can you create an **Anthropic API key** (I'll guide you), or should this wait until
   someone who manages billing can?

Once you've answered those three, I can start on Phase 1.
