# JDN Server Security Tool (JSST)
## Problem
JDN Servers need a method to provision and manage credentials and certificates on the server. This is currently a manual process that is error prone and discourages agile development.

## Solution
JSST will be a binary installed on the server that will manage its credentials to securely interact with
other services.

The command can ran manually via CLI or on a set interval via `cron` or similar tool.

## Commands
```
Commands:
  credentials  Manage the Vault Credentials
  ssh          Manage SSH Key
  gpg-key      Manage Local GPG Encryption Key
  password     Manage Local User Passwords
  crypt        Manage LUKS
  help         Print this message or the help of the given subcommand(s)

Options:
  -o, --output <OUTPUT>  JSST Output Directory [default: /var/lib/jdn/jsst]
  -s, --server <SERVER>  Vault Server [default: https://secrets.jdn-lab.com]
  -v, --verbose          
  -q, --quiet            
  -h, --help             Print help
  -V, --version          Print version
```
