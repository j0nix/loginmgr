# loginmgr

**Simple encrypted storage and manager for logins with small and simple revision handling remove / add / edit entries.**
- Get retreives to clipboard (xclip). 
- Written for linux,

 **Requires python 3+, Python 3.6+ is preferred.**

***Usage:*** loginmgr | loginmgr "entry"

* **loginmgr without entry argument brings you to the shell**

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

**Exampe add:**

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
...


## Build rpm from loginmgr.spec 
1. Go to your build root 
2. Into SOURCES folder, wget https://api.github.com/repos/belsebubben/loginmgr/tarball/master
4. Into SPECS folder, wget https://raw.githubusercontent.com/belsebubben/loginmgr/master/loginmgr.spec
5. rpmbuild --clean -bb SPECS/loginmgr.spec

When finished your build enviroment would like something like this

```
├── BUILD
├── BUILDROOT
├── RPMS
│   ├── noarch
│   │   └── loginmgr-0.12-1.fc24.noarch.rpm
│   └── x86_64
├── SOURCES
│   └── master
├── SPECS
│   └── loginmgr.spec
├── SRPMS
└── tmp
```
