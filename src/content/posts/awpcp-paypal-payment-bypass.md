---
title: "AWPCP <= 4.4.7: Unauthenticated Payment Bypass in the PayPal Standard Return Handler"
date: 2026-07-09
categories: ["Blog"]
tags: ["AWPCP", "WordPress", "Broken Access Control", "PayPal", "Payment Bypass", "Research", "CWE-345", "CVE-2026-65469"]
author: "z3r0s"
draft: false
---

AWPCP treats an INVALID PayPal response as PENDING, but only when it arrives on the user "return" path instead of the server-to-server IPN path. That one asymmetry is the whole bug. An unauthenticated attacker forges the PayPal Standard return for their own transaction, PayPal itself says the callback is invalid, and AWPCP publishes the paid listing anyway. No login, no IDOR, one POST request. I reproduced it live end to end on WordPress 6.8 with an unmodified AWPCP 4.4.7 against the real PayPal validator, not a mock. Its now tracked as **CVE-2026-65469** and fixed in AWPCP 4.4.8 ([Patchstack advisory](https://patchstack.com/database/WordPress/Plugin/another-wordpress-classifieds-plugin/vulnerability/wordpress-awp-classifieds-plugin-4-4-7-broken-access-control-vulnerability)). If you run a paid-classifieds site on AWPCP, update.

## What AWPCP is and how paid listings work

AWP Classifieds (Another WordPress Classifieds Plugin), by WPTasty, lets a WordPress site run paid classified ads. When a site charges for listings it ships a PayPal Standard gateway, and front-end ad posting is on by default, so a random visitor can start the paid flow with no account.

The intended flow is straightforward:

1. A user creates a listing, and AWPCP creates a transaction with an amount due.
2. The user is sent to PayPal to pay.
3. PayPal calls the site back two separate ways.
4. The site confirms the payment is real, and the listing goes live.

Step 3 is where everything hinges, because those two callbacks are not equally trustworthy.

## Two callbacks, one of them is a lie

PayPal Standard tells your site about a payment through two channels:

- The **browser return.** After paying, the buyer's browser gets redirected back to your site with the transaction details in the request. This is attacker-controlled. Its just a request coming from a browser you dont control, carrying data you cant trust.
- The **IPN (Instant Payment Notification).** PayPal's own servers make a separate server-to-server call to your site with the transaction details. This is the channel you actually validate against.

The way you validate either one is the same: you post the body back to PayPal with `cmd=_notify-validate`, and PayPal answers with the literal string `VERIFIED` or `INVALID`. A forged callback comes back `INVALID`, which is correct and expected. The bug is entirely in what AWPCP does with that `INVALID` depending on which channel it came in on.

## The root cause

Here is the handler, `includes/payment-gateway-paypal-standard.php`, `do_process_payment($transaction, $is_ipn)`, lines 297-331:

```php
private function do_process_payment( $transaction, $is_ipn ) {
    if ( $transaction->get( 'verified', false ) ) return;
    if ( ! $this->request->post( 'verify_sign' ) ) {
        $transaction->payment_status = ...NOT_VERIFIED; return;
    }
    $response = $this->verify_transaction( $transaction );   // posts body to PayPal -> "INVALID"
    $transaction->payment_status = ...UNKNOWN;
    if ( 'VERIFIED' === $response ) { $this->validate_transaction(...); return; }
    if ( 'INVALID' === $response ) {
        if ( $is_ipn ) {
            $transaction->payment_status = ...PAYMENT_STATUS_INVALID;   // correct
        } else {
            $transaction->payment_status = ...PAYMENT_STATUS_PENDING;   // BUG
            $transaction->set( 'pending_verification', true );
        }
    }
}
```

Read the `INVALID` branch. On the IPN path (`$is_ipn = true`), an invalid transaction is marked `INVALID`. Correct. On the return path (`$is_ipn = false`), the exact same invalid response is marked `PENDING` and flagged `pending_verification`.

Now here is the part that makes it exploitable rather than merely sloppy. The amount check and the receiver-email check, the two things that would catch "you paid 0.00" or "you paid the wrong PayPal account", live inside `validate_transaction()`, at lines 155 and 163. And `validate_transaction()` only runs on `VERIFIED`. On a forged `INVALID` return it never executes. So the transaction becomes `PENDING` without anyone ever checking that money changed hands or that it went to the right account.

## From PENDING to published

`PENDING` sounds harmless. It isnt, because downstream AWPCP treats pending as good enough at every gate. Four steps:

1. `AWPCP_PaymentsAPI::wp()` runs on `template_redirect`, which fires for any visitor with no auth, and calls `process_payment_request('return')` (payments-api.php:527). The transaction id comes from `get_query_var('awpcp-txn')`, which is the attacker's own transaction.
2. `process_payment_completed()` (payments-api.php:542-578) advances the state machine to `STATUS_PAYMENT_COMPLETED`. Its only guard, `verify_payment_completed_conditions()`, checks that `payment_status` is not empty. `PENDING` is not empty, so it passes.
3. `was_payment_successful()` returns true, because `payment_is_pending()` is true (models/payment-transaction.php:467-471). Pending literally counts as a successful payment here.
4. `set_new_listing_post_status()` (class-listings-api.php:510-524) with `adapprove=0` and `enable-ads-pending-payment=1`, both stock defaults, falls through to `enable_listing()`, and the ad's `post_status` becomes `publish`. Email verification is bypassed in the same path, because `should_mark_listing_as_verified()` also keys off `payment_is_pending()`.

Every gate asks "is there a payment status?" and none of them asks "did PayPal actually verify it?"

## The proof of concept

The transaction id is the attacker's own. Its right there in the return and notify URLs, and in the custom field of the PayPal form once the payment step is reached. Call it `T`.

Before the attack:

```
LISTING (id 13) post_status = disabled (not visible)
transaction payment_status = NULL (unpaid)
was_payment_successful() = false
amount due = 25.00, amount paid = 0.00
```

The entire attack is one unauthenticated request:

```
POST /awpcpx/payments/return/31005da187957d668efa0a32a053d7b6
Content-Type: application/x-www-form-urlencoded

verify_sign=x
```

The server forwards that forged body to the live PayPal validator at `https://ipnpb.paypal.com/cgi-bin/webscr` as `cmd=_notify-validate&verify_sign=x&...`. PayPal replies `INVALID` with HTTP 200, exactly as it should. Because this is the return action and not an IPN, AWPCP sets `payment_status = PENDING` and responds `302` to `?step=payment-completed&transaction_id=T`.

After the attack:

```
LISTING (id 13) post_status = publish (PUBLISHED)
listing verified = true (email verification bypassed)
transaction status = Payment Completed
was_payment_successful() = true
amount paid = 0.00 (still nothing paid)
```

A paid, email-verified listing, for free, with a single request from someone who never logged in.

## Why the neighboring code is fine

Two things next to this bug are worth calling out, because they show it isnt a systemic failure, its one branch.

The IPN path is correct. With `$is_ipn = true`, `INVALID` stays `INVALID`. If PayPal's own server tells you the transaction is bogus, AWPCP believes it. The only broken channel is the attacker-controlled one.

The 2Checkout gateway is also fine. It requires an MD5 `hash_equals` match before it will validate anything, and it drops to `UNKNOWN` on failure rather than to a pending-but-successful state. So the pattern "verify authenticity first, and treat failure as not-successful" was available in the same codebase. PayPal Standard just didnt follow it on the return path.

## Preconditions and where it came from

The preconditions are common, not exotic. You need `freepay=1` (the site charges for listings, which is the entire reason the PayPal gateway exists), PayPal Standard active with a PayPal email set, and moderation left at stock defaults (`adapprove=0`, `enable-ads-pending-payment=1`). That is a default paid-classifieds install.

This got introduced in 4.4.4, with the `pending_verification` feature. The feature added a legitimate "we are waiting on confirmation" state, and the return handler started routing invalid callbacks into it instead of rejecting them. A feature meant to be lenient about timing became lenient about authenticity.

## The fix

On the user return path, an `INVALID` result must not be treated as pending or successful. Keep the status non-successful (`UNKNOWN` / `NOT_VERIFIED`) and, at most, show a "waiting for confirmation" notice. Do not let `was_payment_successful()` pass until a genuine `VERIFIED` IPN arrives from PayPal's servers. Reserve `PENDING` for responses that were actually `VERIFIED` with `payment_status = Pending`, which is what pending was supposed to mean in the first place.

This is a business-logic bug more than a technical one. Nothing got smashed, no bounds got exceeded, no signature got forged. The code simply decided that "PayPal says this is invalid" plus "but it came in through the browser" adds up to "probably fine, publish it". That is the kind of bug you only see by asking what each state means and who gets to set it, not by fuzzing.

*Found by z3r0s (https://github.com/z3r0s6) via manual source review. CVE-2026-65469, CVSS 5.3, CWE-345 (Insufficient Verification of Data Authenticity) with CWE-840 (Business Logic Errors). Affected AWPCP <= 4.4.7, fixed in 4.4.8. Reproduced on WordPress 6.8, AWPCP 4.4.7, PHP 8.4.*
