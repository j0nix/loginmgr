#loginmgr
simple encrypted storage and manager for logins with small and simple revision handling remove / add / edit entries. Get retreives to clipboard (xclip). Written for linux,
Requires pythohn 3+. Python 3.6+ is preferred.

Usage: loginmgr | loginmgr "entry"

loginmgr without entry argument brings you to the shell

Shell cli
```
Documented commands (type help topic):
========================================
add  cat  dump  edit  get  help  ls  q  quit  revls  revopen  rm  search

"add" Bring you to the login entry add prompt

"cat <name>" (Dump all existing information of a login entry)

"dump" dump everything

"edit <name>" (Edit the properties of a login entry)

"get <name>" (Get a login entry) copy pw to clipboard however do not show it

"ls <text> | ls " list all entries names (no argument) or if specified list details of one specific

"quit" quit, encrypt and save. If there was changes a new revision will be saved and the oldest one rotated out

"revls" list available revisions, and deleted entries

"revopen <nr>" open available revision (read only)
Password that was used to encrypt that revision must be provided (maybe not the same as for the current one)

"rm <name>" (Remove the properties of a login entry)

"search <text>" Search all logins for a match, and inside all key/values for a match too
```

exampe add:

```
loginmgr:add secretsite.com
Login for secretsite.com:loginname@my.domain.com
Password for "secretsite.com" empty for suggested (aB1cpmJP75yLVemSx91V-E4lvHeJ):
Extra parameter for:secretsite.com (empty to exit):belsebubben
Value for belsebubben:1
Extra parameter for:secretsite.com (empty to exit):
secretsite.com:
name        : secretsite.com
login       : loginname@my.domain.com
password    : -
belsebubben : 1
Save entry y/n? y
```

example rm:
