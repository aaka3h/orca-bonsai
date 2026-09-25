#!/usr/bin/env bash
set -Eeuo pipefail

# sudo -A runs this helper only for administrator authentication. The password
# goes from Zenity directly to sudo; the chat process never reads or logs it.
exec zenity --password \
    --title='Orca Bonsai administrator access' \
    --text='Enter your account password to authorize this administrator action.'
