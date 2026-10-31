# Where to change things, per mail stack

Back up every file before editing, validate the configuration, then reload.
Never restart the MTA with a broken config: it stops accepting mail.

## HELO / EHLO name

| Stack | Setting |
|---|---|
| Postfix | `postconf -e 'smtp_helo_name = mail.example.com'` (default is `$myhostname`), then `postfix check && systemctl reload postfix` |
| Exim (Debian) | `MAIN_HARDCODE_PRIMARY_HOSTNAME` in `/etc/exim4/update-exim4.conf.conf` or `primary_hostname`, then `update-exim4.conf && systemctl reload exim4` |
| Exim (generic) | `primary_hostname = mail.example.com`, or `helo_data` on the remote_smtp transport |
| cPanel | WHM > Basic WebHost Manager Setup / Change Hostname (server-wide); per-domain HELO and IP via WHM Exim Configuration Manager ("Reference /etc/mailhelo" and "/etc/mailips"); never edit exim.conf directly |
| Plesk | Tools & Settings > Mail Server Settings; HELO follows the server host name |
| DirectAdmin | server hostname; per-domain IPs via `/etc/virtual/domainips` and `helo_data` in exim.conf custom parts |

The HELO name needs an A record pointing to the sending IP, and the IP's PTR should
point back to it.

## Outbound IPv6

If the server has IPv6 but no PTR for it, mail to Gmail (and others) goes over IPv6
and fails PTR checks. Either get an IPv6 PTR and add `ip6:` to SPF, or send over IPv4 only:

- Postfix: `postconf -e 'inet_protocols = ipv4'` (or `smtp_address_preference = ipv4` to prefer IPv4)
- Exim: `disable_ipv6 = true`, or `dns_ipv4_lookup = *` to ignore AAAA records for delivery
- cPanel: WHM > Exim Configuration Manager has an IPv6 option for outbound; check before editing

## DKIM signing

| Stack | How |
|---|---|
| cPanel | WHM/cPanel > Email Deliverability: generates the key, shows the exact record, "Repair" can publish it when the server hosts the DNS |
| Plesk | Mail Settings per domain > "Use DKIM spam protection system to sign outgoing email messages" |
| DirectAdmin | DNS Management / E-mail Accounts > DKIM, or `dkim_create.sh` |
| Postfix | OpenDKIM (KeyTable, SigningTable, TrustedHosts, milter on 127.0.0.1) or rspamd `dkim_signing.conf`, added to `smtpd_milters` and `non_smtpd_milters` |
| Exim | `dkim_domain`, `dkim_selector`, `dkim_private_key` on the remote_smtp transport |
| Microsoft 365 | Defender portal > Email authentication > DKIM: publish the two selector CNAMEs, then enable |
| Google Workspace | Admin > Apps > Gmail > Authenticate email: generate, publish TXT, then "Start authentication" |
| ESPs (SendGrid, Mailchimp, Brevo, Postmark, Amazon SES ...) | "Domain authentication": publish their CNAMEs so they sign with d=your domain |

## Stopping a spam source before delisting

Delisting while spam still flows gets the IP relisted, often for longer.

- Compromised mailbox (one authenticated user sends far more than normal): reset its
  password, end its sessions, check its forwarders and filters, then clear its
  queued messages.
  - Exim: `exiqgrep -i -f USER@DOMAIN | xargs exim -Mrm`
  - Postfix: find the queue IDs with `postqueue -p`, then remove them with `postsuper -d ID`
- Script sending (cPanel `cwd=/home/USER/...`): find the script (contact form, a
  compromised WordPress, an uploaded mailer), disable it, clean the site.
- Open relay: test from outside. Postfix `smtpd_relay_restrictions` must end in
  `reject_unauth_destination`.
- Show the user the queue commands, and run them only after they approve:
  deleting from the queue is irreversible.

## Log locations

| Stack | Log |
|---|---|
| cPanel / RHEL Exim | `/var/log/exim_mainlog` |
| Debian Exim | `/var/log/exim4/mainlog` |
| Postfix RHEL | `/var/log/maillog` |
| Postfix Debian/Ubuntu | `/var/log/mail.log` |
| journald only | `journalctl -u postfix --since -1d`, or `-u exim4` |
| Plesk | `/var/log/maillog` (Postfix) |
