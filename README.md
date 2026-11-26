# Web Directory Search — `ds.php`

A single-file, password-gated file browser with a built-in PDF/Office document viewer.

## What changed in this redesign

**Design**
- Full visual rebuild with a single typeface — **Noto Sans** (weights 400–800) — replacing the old Playfair Display + DM Sans pairing.
- New light "paper + navy + gold" theme, cleaner card system, consistent spacing tokens.
- True responsive layout: sidebar collapses on tablets/phones, top bar restructures, modal goes full-screen on mobile, search bar wraps instead of overflowing.
- Simplified nav (single sticky top bar) instead of the old header + hamburger dropdown + separate desktop sidebar duplication.

**Submission logic**
- Login form now disables its button and shows a spinner while submitting (prevents double-submits).
- Search form validates the 3-character minimum client-side before submitting, with an inline shake/red-border cue, in addition to the existing server-side check.
- Search button also disables + shows a spinner while a request is in flight.
- Viewer retry logic capped at a fixed number of attempts (`MAX_RETRIES`) instead of retrying forever, with a clear error state and "Open directly" fallback.

**Security / credentials**
- Password is no longer hashed on every request via `password_hash()` in-line — it is now a **pre-computed constant** (`HASHED_PASSWORD`), which is the correct pattern (hashing on every page load is wasteful and was previously regenerating a *different* hash each time since no fixed salt was pinned to a config value).
- Default password changed to **`admin123`**, stored only as its Argon2id hash:
  ```
  $argon2id$v=19$m=65536,t=4,p=1$UTNSTnY0eHdUZlJ2TEtQRw$Cg4GLepFW/pEq+tLPrkB7WDfgU+YvUfgd2Rx69G5oTk
  ```
- All original protections kept intact:
  - CSRF tokens (regenerated every attempt)
  - Session fixation protection (`session_regenerate_id`)
  - Rate limiting: 5 attempts → 5 min lock, 10 attempts → 24h lock
  - 30-minute absolute session expiry
  - `password_verify()` constant-time comparison
  - Security headers: `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, no-cache
  - Path traversal / sensitive file exclusion list in search (`config.php`, `.htaccess`, `.git`, etc.), plus `ds.php` itself is now excluded from its own search results.

## Changing the password

Generate a new Argon2id hash:

```bash
php -r "echo password_hash('yourNewPassword', PASSWORD_ARGON2ID), PHP_EOL;"
```

Then replace the `HASHED_PASSWORD` constant near the top of `ds.php`:

```php
const HASHED_PASSWORD = '<paste new hash here>';
```

Never store the plaintext password anywhere in the file.

## How it works

1. **Login** — user submits a password → verified against `HASHED_PASSWORD` with `password_verify()`. On success, session is regenerated and marked authenticated.
2. **Search** — authenticated users can recursively search all files under the script's directory (excluding sensitive/system files and folders). Minimum 3 characters.
3. **Viewing** — clicking a result:
   - PDFs open in an embedded **Google Docs Viewer** iframe.
   - Office files (`doc/docx/ppt/pptx/xls/xlsx/odt/odp/ods`) open in the **Microsoft Office Online Viewer**.
   - Everything else opens directly in a new tab.
   - The viewer auto-retries a few times (Google → Office fallback for PDFs) before showing an error state with manual retry / open-directly options.
4. **Logout** — destroys the session and starts a fresh one.

## Requirements

- PHP 7.4+ (uses `PASSWORD_ARGON2ID`, so the `sodium` or built-in Argon2 support must be compiled in — standard on most modern PHP builds).
- No database or external dependencies — everything is session + filesystem based.

## File layout expectations

The script searches recursively from its own directory (`__DIR__`). Excluded by default:

- Files: `.htaccess`, `.htpasswd`, `config.php`, `settings.php`, `database.php`, `admin.php`, `sr.php`, `viewer.aspx`, `admin-profile.aspx`, `ds.php`, `srs.php`
- Directories: `.private`, `.archive`, `.git`, `node_modules`, `vendor`

Adjust the `$excludedFiles` / `$excludedDirs` arrays near the top of the script as needed for your deployment.
