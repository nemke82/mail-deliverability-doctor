# DNS records: rules and common mistakes

## SPF (RFC 7208)

- Exactly **one** TXT record starting `v=spf1` per name. Two records = permerror = SPF fails everywhere.
- At most **10** DNS-querying terms in total, nested includes included:
  `include`, `a`, `mx`, `ptr`, `exists`, `redirect`. `ip4`, `ip6` and `all` are free.
  Over the limit = permerror. At most 2 "void" lookups (names that do not exist).
- End with `~all` (softfail) or `-all` (fail). `+all` authorizes the whole internet;
  `?all` authorizes nothing in particular. With DMARC enforcing, `~all` is enough.
- `ptr` is deprecated: slow and ignored by many receivers. Replace it with ip4/ip6.
- SPF checks the **envelope sender** (Return-Path / MAIL FROM), not the visible From.
  An ESP that uses its own bounce domain passes SPF for itself, which does not help
  DMARC for your From domain; set up its "custom return-path" / "custom bounce domain".
- Too many lookups: remove includes of services no longer used, replace stable
  includes with their ip4/ip6 ranges (re-check them periodically), or move some
  senders to a subdomain (news.example.com) with its own SPF.
- The HELO name should have SPF too (`v=spf1 a -all`): bounces with an empty
  envelope sender are checked against the HELO name.
- Records over 255 characters must be stored as several quoted strings in one TXT
  record; receivers join them without spaces.

## DKIM (RFC 6376)

- Public key at `SELECTOR._domainkey.DOMAIN` TXT: `v=DKIM1; k=rsa; p=BASE64`.
- 2048-bit RSA is the norm; 1024 still works but is weak; under 1024 is ignored.
- The selector is in the `s=` tag of the `DKIM-Signature` header; the signing
  domain is `d=`. DMARC needs `d=` to match the From domain (relaxed: same
  organizational domain).
- Rotation: publish the new selector, switch the signer, keep the old key published
  for a few days, then remove it (or publish an empty `p=` to revoke).
- Signatures break when something modifies the message after signing: footers,
  disclaimers, link rewriting, antivirus banners, re-encoding by a relay.
- Providers often publish DKIM as CNAMEs (Microsoft 365 selector1/selector2,
  SendGrid s1/s2, Mailchimp k1). That is normal.

## DMARC (RFC 7489)

- Record at `_dmarc.DOMAIN`: `v=DMARC1; p=none|quarantine|reject; rua=mailto:...`.
- Passes when **SPF passes with an aligned envelope domain** or **DKIM passes with an
  aligned d=**. One is enough; DKIM is the one that survives forwarding.
- Subdomains without their own record inherit from the organizational domain,
  using `sp=` if set.
- `rua` to a mailbox in another domain needs that domain to publish
  `YOURDOMAIN._report._dmarc.THEIRDOMAIN TXT "v=DMARC1"`; DMARC services do this
  automatically.
- Roll out: `p=none` with reports, fix every legitimate sender, then
  `p=quarantine` (optionally `pct=` to stage), then `p=reject`.
- `p=reject` before all senders are aligned silently loses real mail (invoices,
  password resets, CRM). Read the reports first.

## MX

- Hosts, not IPs or CNAMEs. Each host needs A and/or AAAA.
- A domain that never receives mail can publish a null MX: `0 .`.

## MTA-STS and TLS-RPT (RFC 8461, RFC 8460)

- `_mta-sts.DOMAIN TXT "v=STSv1; id=..."` plus a policy file at
  `https://mta-sts.DOMAIN/.well-known/mta-sts.txt` (valid HTTPS certificate required).
- Every MX must match an `mx:` line in the policy. In `enforce` mode, senders refuse
  MXes that do not match or whose certificate does not verify.
- Start with `mode: testing` and `_smtp._tls.DOMAIN TXT "v=TLSRPTv1; rua=mailto:..."`
  to receive failure reports.
- Change `id=` whenever the policy file changes.

## BIMI

- `default._bimi.DOMAIN TXT "v=BIMI1; l=https://.../logo.svg; a=https://.../vmc.pem"`.
- Requires DMARC at quarantine or reject (pct=100). Gmail and Apple also require a
  VMC or CMC certificate; Yahoo shows logos for some senders without one.

## Reverse DNS (PTR)

- Set by whoever owns the IP block (hosting provider panel or ticket), not in
  your domain's DNS zone.
- One PTR per IP, pointing to the server's mail host name, and that name must
  resolve back to the same IP (forward-confirmed reverse DNS).
- Use the same name as the server's HELO/EHLO. Avoid generic names containing the
  IP digits.
- Every IPv6 address used for outbound mail needs its own PTR and an `ip6:` SPF entry.
