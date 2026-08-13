---
title: "How I Bypassed OAuth Consent in Privy's Cross-App Connection Flow"
date: 2026-07-16
categories: ["Blog"]
tags: ["Privy", "OAuth", "Web3", "Access Control", "HackerOne", "Research"]
author: "z3r0s"
draft: false
---

OAuth consent is the users last line of defense. Its the one screen where a person gets to look at an app asking for access and say "no". Everything else in the flow is machinery. That one click is the whole point. So when the "no" button does the exact same thing as the "yes" button, the machinery is lying to you.

That is basically what I found in Privy's cross-app connection system. The reject flow generates a fully valid authorization code, same as accept. The rejection is cosmetic. Let me walk through how I got there.

## Where I was looking

I was auditing the npm package `@privy-io/cross-app-provider`, version 0.3.7. Privy powers embedded wallets for a lot of Web3 apps, and the cross-app piece is how one dApp connects to a wallet that lives inside another Privy app. Its OAuth under the hood, with PKCE. Standard enough that you expect the standard guarantees.

I pulled the package and started reading the ESM build in `dist/esm/auth/`. Two files jumped out immediately: `accept-connection.mjs` and `reject-connection.mjs`.

Here is the thing about accept and reject in any OAuth consent flow: they are supposed to be different operations at a fundamental level. Accept means "issue a credential". Reject means "issue nothing, tell the client the user said no". Those are not two flavors of the same request. One creates a code, one must not. So when I saw two separate files I opened them side by side and just read them line for line.

## What the two files actually do

Both functions POST to the same endpoint: `/api/oauth/v2/authorization_code`. Same body. Same `state`, `code_challenge`, `code_challenge_method`, `oauth_client_id`. Same headers, same `credentials: "include"`. Same response, a redirect URL that contains a real authorization code.

The only difference is what `rejectConnection()` does with the response after it already has the code:

```javascript
const rejectConnection = async ({ accessToken, appClientId, appId,
    codeChallenge, codeChallengeMethod, oauthClientId, privyDomain, state }) => {
  let url = new URL(`${privyDomain}/api/oauth/v2/authorization_code`);
  let response = await fetch(url, {
    method: "POST",
    headers: headers,
    body: JSON.stringify({
      state: state,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
      oauth_client_id: oauthClientId
    }),
    credentials: "include"
  });
  let { location } = await response.json();
  let redirectUrl = new URL(location);
  redirectUrl.searchParams.set("error", "user_canceled_connection");
  return { location: redirectUrl.href };
};
```

`accept-connection.mjs` is the same request. It just returns `await response.json()` directly and doesnt bolt on the error param.

So the "rejection" is one line: `redirectUrl.searchParams.set("error", "user_canceled_connection")`. The server already minted the authorization code by the time that line runs. The reject function decorates the redirect URL with an error string and hands back a URL that still carries a valid code.

## Why the server cant tell the difference

This is the part that makes it architectural instead of a small oversight. The server has no signal. Accept and reject send byte-identical requests. There is no `consent: true/false` field, no separate endpoint, nothing. The decision about whether the user consented is made entirely on the client, after the credential already exists. From the servers point of view every reject is an accept.

## PKCE doesnt save you here

The first objection people raise is "so what, PKCE". PKCE stops an attacker who intercepts an authorization code from redeeming it, because they dont have the `code_verifier`. But look at who the attacker is in this flow. The requester app is the party that generated the PKCE `code_verifier` in the first place. The attacker IS the legitimate PKCE client. It receives the code in its own callback, it has its own verifier, it completes the token exchange like normal and gets a provider access token.

PKCE protects the code in transit between honest parties. It does nothing when the party that is supposed to respect the users "no" is the one ignoring it.

## The attack, start to finish

1. A malicious dApp starts a cross-app connection to the victims Privy account. It generates the PKCE pair like any legit requester.
2. The consent popup shows up. The victim reads it and clicks Reject.
3. `rejectConnection()` fires, hits `/api/oauth/v2/authorization_code`, and the server issues a real authorization code inside the redirect URL.
4. The malicious app receives the redirect at its callback. It ignores the `error=user_canceled_connection` param. Reads the `code`.
5. It runs the token exchange with its own `code_verifier`. Gets a provider access token.
6. The connection is now live. The user said no and the connection exists anyway.

Once its established the app keeps the relationship, can throw transaction-signing popups through the cross-app wallet flow, and can quietly re-establish if the user disconnects, because rejecting the re-connection prompt does the same nothing.

## What the RFC says

This isnt a gray area. RFC 6749 section 4.1.2.1 is explicit: if the user denies the request, the authorization server SHOULD redirect with `error=access_denied` and MUST NOT include an authorization code. Privy issues the code on denial. The `MUST NOT` is the part being broken, and its broken on the server, the client library just papers over it.

## Impact

A malicious dApp establishes a cross-app connection to a users Privy-powered account after the user explicitly denied it. With the token it holds a persistent unauthorized cross-app relationship, can present transaction signing UI through the wallet flow, and can re-establish the connection on demand. The users only defense, the consent screen, does not defend anything.

Scored it High, 8.2.

CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N

## The fix I recommended

Any of three, and they get cheaper as you go down:

- **A.** Reject calls a real endpoint, something like `/api/oauth/v2/reject`, that does not mint a code.
- **B.** Add a `consent_granted: boolean` to the request body so the server can branch on it.
- **C.** Dont make a server call on reject at all. Just redirect with the error and no code. The user said no, there is nothing to ask the server for.

Option C is my favorite because it matches the mental model: rejection is the absence of a credential, not a credential with a sticker on it.

## Takeaway

When you split accept and reject into two functions, its really easy to make reject "accept, but with an error label". It reads fine in review, both functions return a `location`, both look like they do their job. But consent is a server-side decision about whether to issue a credential, and if the reject path can produce the same credential as accept, you dont have a consent screen. You have a button that shows the user an error message while doing exactly what they told it not to.
