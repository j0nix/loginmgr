#!/usr/bin/python3
'''Simple password manager devil style

About shredding
https://access.redhat.com/solutions/2109901
shred command will work on xfs filesystem. We know its a journald
filesystem and in the man page of shred its mentioned that shred is not
effective, or is not guaranteed to be effective.  Well in xfs the journal
stores the metadata and not the content of the file in it and you can tell
shred to run ~20 times using random numbers, zeroes and delete the file
when it finished.  Journal will log the transactions issued by shred
against the file not the contents.

1. Handle files with backups
    a. files should be backed up with N copies. Only when changes were done
    b. link to the latest backup should be handled as the latest copy

2. Encryption and decryption
    a. Program should not be allowd to terminate with decrypted content
    b. Encryption and decryption method should be pluggable

3. Storage of entries
    a. entries should be able to arbitrary key: values
    b. each entry must have a utf-8 encoded name as key
    c. the value for that should be an dictionary
    try json ... try sqlite

4. command line should be able to encrypt / decrypt
    1. add / edit / remove entries
    2. edit add keys to existing entries

'''

import sys
import json
import os
from io import StringIO
from io import BytesIO
import time
import atexit
import signal
from glob import glob
import string
import subprocess
import argparse
import random
import shutil
import getpass
import base64
import readline
import cmd
import logging
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DEBUG = True
WORK_PATH = '/home/carl/Code/loginmgr/TEST/'
FNAME = 'testfile.crypt'
BKUPNR = 10 # nr of backups to keep
SPECIAL_CHARS = '_!?.&+-'
STARTDIR = os.getcwd()
PWLEN = 20
saltlength = 16
LOGFORMAT = '%(asctime)s %(levelname)s: %(message)s'
LOGFORMATDEBUG = '%(asctime)s %(levelname)s: line:%(lineno)d  func:%(funcName)s;  %(message)s'
logger = logging.getLogger('loginmgr')
COLORS = {'grey': '\033[1;30m', 'red':'\033[1;31m', 'green':'\033[1;32m', 'yellow':'\033[1;33m',\
        'brown':'\033[0;33m', 'blue':'\033[1;34m', 'magenta':'\033[1;35m', 'cyan':'\033[1;36m', 'white':'\033[1;37m', 'stndrd':'\033[0m'}
filtered_meta = ('META', 'SALT', 'old_revisions', 'ctime', 'mtime')

if DEBUG:
    logger.setLevel(logging.DEBUG)
    logger.debug('Debugging enabled')
    logging.basicConfig(format=LOGFORMATDEBUG, stream=sys.stderr) # add logfile option
else:
    logging.basicConfig(format=LOGFORMAT, stream=sys.stderr) # add logfile option
    logger.setLevel(logging.INFO)

def parseargs():
    '''
    argument parsing
    '''
    parser = argparse.ArgumentParser(description='Login database manager.')
    parser.add_argument('-P' '--path', dest='path', action='store', default='TEST',\
            help='path to directory')
    parser.add_argument('-P' '--provider', dest='provider',\
            action='store', default='file', help='Base storage method')
    parser.add_argument('-s' '--setup', dest='setup', action='store_true',\
            default=False, help='Base storage method')
    args = parser.parse_args()
    return args

def maxstrlen(maxlenlist):
    return max([len(string) for string in maxlenlist])

def complexitycheck(pwd):
    '''
    >>> complexitycheck('123')
    False
    >>> complexitycheck('123AVCavc+1-')
    True
    '''
    pwd = set(pwd)
    asciiset = set(string.ascii_letters)
    digiset = set(string.digits)
    upperset = set(string.ascii_uppercase)
    digiset = set(SPECIAL_CHARS)
    for testcase in (asciiset, digiset, upperset, digiset):
        if len(testcase & pwd) < 1:
            return False
    return True

def genpwd(length=20):
    '''
    >>> type(genpwd())
    <class 'str'>
    '''
    pwd = ''.join(random.sample(string.ascii_letters * 7 + string.digits * 7 +\
            SPECIAL_CHARS, k=length))[:length]
    while not complexitycheck(pwd):
        pwd = ''.join(random.sample(string.ascii_letters * 7 + string.digits *\
                7 + SPECIAL_CHARS * 2, k=length))[:length]
    return pwd

def salter():
    '''Add crap section'''
    return genpwd(200)

def pwpassprompt(decrypt=False):
    '''Prompt for password'''
    if decrypt:
        pass1 = getpass.getpass('Password:')
    else:
        pass1 = None
        pass2 = None
        while pass1 != pass2 or not pass1:
            pass1 = getpass.getpass('Password:')
            pass2 = getpass.getpass('Repeat password:')
            if pass1 != pass2:
                print('Password mismatch!!')
    logger.debug('Using password "%s"', pass1)
    return str.encode(pass1)

def enryption_tokenizer(encpassbase, salt=None):
    '''
    >>> enryption_tokenizer() #doctest: +ELLIPSIS
    <cryptography.fernet.Fernet object...
    '''
    if not salt:
        salt = os.urandom(16)
    logger.debug('Encrypt/Decrypt with salt: "%s"', salt)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,\
            iterations=100000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(encpassbase))
    enckey = Fernet(key)
    logger.debug('Using encryption key "%s"', str(enckey))
    return (enckey, salt)

def decrypt(byteobj):
    salt = byteobj[:saltlength]
    encbytes = byteobj[saltlength:]
    logger.debug('Decrypting with salt: "%s"', salt)
    encpassbase = pwpassprompt(decrypt=True)
    decryptiontoken, salt = enryption_tokenizer(encpassbase, salt)
    logger.debug('Type byteobj: %s', type(encbytes))
    try:
        decryptedbytes = decryptiontoken.decrypt(encbytes)
    except TypeError:
        logger.critical('Failed to decrypt content, content corrupted?!?!')
        #todo implement recovery (suggestions and action)
        raise
    except InvalidToken:
        logger.warning('Wrong password')
        decrypt(encbytes)
    return decryptedbytes

def encrypt(byteobj):
    encpassbase = pwpassprompt(decrypt=False)
    encryptiontoken, salt = enryption_tokenizer(encpassbase)
    logger.debug('Type byteobj: %s', type(byteobj))
    encbytes = encryptiontoken.encrypt(byteobj)
    logger.debug('Encrypted bytes with password')
    return salt + encbytes

def shredder(filepath):
    '''
    >>> shredder('/tmp/testfile') #doctest: +ELLIPSIS
    Warning!!! Failed to shred contents of file...
    >>> open('/tmp/testfile', 'w').write('mooooo')
    6
    >>> shredder('/tmp/testfile') #doctest: +ELLIPSIS
    Shredded /tmp/testfile
    '''
    command = ['shred', '-n', '20', '-v', '-f', '-z', '-u', filepath]
    new_env = os.environ.copy()
    scmd = subprocess.Popen(command, env=new_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, stderr = scmd.communicate()
    if scmd.returncode != 0:
        print('Warning!!! Failed to shred contents of file:', filepath, ';', stderr)
    else:
        print('Shredded {0}'.format(filepath))

def backtodir():
    os.chdir(STARTDIR)

def fullbackup(pathtodir):
    '''Tar / zip and point to full backup of dir'''
    pass

#def to_clipboard(text):
    #cb = Gtk.Clipboard.get(Gdk.SELECTION_PRIMARY)
    #cb = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
    #cb.connect('owner-change',test)
    #cb.set_text('foooo', -1)
    #cb.store()

def to_clipboard(text):
    try:
        xclipper = subprocess.Popen(['xclip', '-selection', 'c'], stdin=subprocess.PIPE, close_fds=True)
    except FileNotFoundError:
        logger.warning('Failed to copy password to clipboard (need "xclip" application)')
    _, stderr = xclipper.communicate(text.encode('utf-8'))
    if xclipper.returncode != 0:
        logger.warning('Failed to copy password to clipboard:', stderr)

#def decrypt(filesys):
#    if filesys.initializing:
#        return filesys.bytecontent
#    decryptiontoken = enryption_tokenizer()
#    logger.debug('Type byteobj: %s', type(byteobj))
#    try:
#        decryptiontoken.decrypt(byteobj)
#    except TypeError:
#        logger.critical('Failed to decrypt content, content corrupted?!?!')
#        #todo implement recovery (suggestions and action)
#        raise
#    except InvalidToken:
#        logger.warning('Wrong password')
#        decrypt(byteobj)

def quit(filesys, logins):
    logger.debug('Quitting with logins: {0}, filesys: {1}'.format(logins, filesys))
    encryptedbytes = encrypt(logins.save())
    filesys.feedandsave(encryptedbytes, logins)

class Login():
    def __init__(self):
        self.data = {}
        #self.date = ""
        #self.login = ""
        #self.password = ""
        #self.description = ""

    def __str__(self):
        return self.data

    def edit_pw(self):
        pass

    def edit_login(self):
        pass

class Logins():

    def setupdated(self, edit, remove, login):
        self.changed = True
        if self.revision == self.newrevision:
            self.newrevision = self.revision + 1
        if edit:
            self.edited.append(login)
        elif self.remove:
            self.removed.append(login)
        else:
            self.added.append(login)

    def add(self, config={}, edit=False):
        '''Add a login entry (dict('name': {}))'''
        if not 'name' in config:
            logger.warning('entry {0} has no "name" configured', config)
        if config['name'] in self.logins and not edit:
            logger.warning('%s already present, use another name or update entry', config['name'])
            return

        login = {}
        if not edit:
            login['ctime'] = time.time()
        if edit:
            # Some info so that we can retreive last editions
            login['mtime'] = time.time()
            if 'old_revisions' in login:
                login['old_revisions'].append(self.revision) 
            else:
                login['old_revisions'] = [self.revision]
        for k, v in config.items():
            if k == 'name':
                next
            if edit:
                if not v:
                    pass
                else:
                    login[k] = v
            else:
                login[k] = v
        if not 'login' in login:
            logger.warning('No login set for %s', config['name'])
        if not 'password' in login:
            logger.warning('No password set for %s', config['name'])

        self.logins[config['name']] = login
        self.setupdated(edit, remove=False, login=login)

    def edit(self, config={}):
        self.add(config={}, edit=True)

    def remove(self, name):
        try:
            removed = dict(((name, self.logins.pop(name)), ))
        except KeyError:
            logger.warning('%s is not a configured login', name)
            return False
        self.setupdated(edit=False, remove=True, login=removed)
        logger.warning('Logins can be restored from older revisions\
                (i.e history files use "search-history" command to find entries)', name)
        logger.warning('Removed login %s', name)
        return True

    def loginprinter(login, pwhide=True, clipboard=False, filtermeta=True):
        printfirstkeys = ('name', 'login', 'password')
        print('{0}:'.format(login['name']))
        maxlen = str(maxstrlen(login.keys()))
        printrest = [key for key in login.keys() if key not in printfirstkeys]
        printlist = []

        for key, val in login.items():
            strformat = '{0:<' + maxlen + '} : {1}'
            if filtermeta and key in filtered_meta:
                continue
            if 'login' in key:
                strformat = COLORS['green'] + strformat + '\033[1;m'
                printlist.insert(1, strformat.format(key, '-' if pwhide and key == 'password' else val))
            elif 'password' in key:
                strformat = COLORS['red'] + strformat + '\033[1;m'
                printlist.insert(2, strformat.format(key, '-' if pwhide and key == 'password' else val))
                if clipboard:
                    to_clipboard(val)
            elif 'name' in key:
                strformat = COLORS['blue'] + strformat + '\033[1;m'
                printlist.insert(0, strformat.format(key, '-' if pwhide and key == 'password' else val))
            else:
                printlist.append(strformat.format(key, '-' if pwhide and key == 'password' else val))
            #print(strformat.format(key, '-' if pwhide and key == 'password' else val))
        for printout in printlist:
            print(printout)


    def load(self, byteobj):
        '''Take in bytes decode json to logins data
        >>> load(b"{'name': 'META', 'password': 'META', 'login': 'META', 'revision': 123}")
        "{'name': 'META', 'password': 'META', 'login': 'META', 'revision': 123}"
        '''
        self.logins = json.loads(byteobj.decode())
        self.revision = self.logins['META']['revision']
        self.newrevision = self.revision
        logger.debug('Loaded object: "%s"', self.logins)

    def to_bytes(self):
        '''This should just give a byts object containing the self.data'''
        return json.dumps(self.logins, sort_keys=True).encode()

    def to_json(self):
        return json.dumps(self.logins, sort_keys=True)

    def save(self):
        self.logins['SALT'] = {'name': salter()}
        self.logins['META']['revision'] = self.newrevision
        logger.debug('Saving object "%s"', self.logins)
        return self.to_bytes()

    def __init__(self, byteobj, initializing=False):
        self.changed = False
        self.removed = []
        self.edited = []
        self.added = []
        if initializing:
            self.logins = {}
            self.revision = 1
            self.newrevision = 1
            firstlogin = self.add({'name': 'META', 'password': 'META', 'login': 'META', 'revision': self.revision } )
        else:
            if byteobj:
                self.load(byteobj)

#### Filesystem handling ####

class FileSysHandler():
    saveformat = '%Y-%m-%d-%H%M%S.enc'
    def clean_backups(self):
        if self.initializing:
            return
        try:
            os.remove(self.filepath + '.bkup')
        except FileNotFoundError:
            pass
        except Exception:
            logger.warning('Unable to remove backup file %s', self.filepath + '.bkup')
        self.oldbackups = glob('*.enc')
        self.oldbackups = sorted(self.oldbackups, key=lambda x: time.strptime(x,\
                self.saveformat), reverse=True)
        if len(self.oldbackups) > BKUPNR:
            self.cleanbkups = self.oldbackups[10:]
            for f in self.cleanbkups:
                logger.info('Cleaning old backup: %s' % f)
                os.remove(f)
        else:
            logger.debug('No cleaning of backups needed')

    def remove_initialcontent(self):
        try:
            os.unlink(self.encryptedpath)
        except Exception as exc:
            logger.warning('Failed to remove file {0}', self.encryptedpath)

    def feedandsave(self, byteobj, logins):
        '''takes in the content (likely encrypted bytes) and saves it as the
        newest save that means that it has to be different than what was opened
        first.
        >>> feedandsave(self, b'abc123')
        '''
        #self.revisionpath = os.path.realpath('revision-' + str(logins.newrevision))
        self.revisionpath = WORK_PATH + 'revision-' + str(logins.newrevision)
        if logins.newrevision == logins.revision:
            # if there was no edit we use the old file paths
            self.savepath = self.filepath
            shutil.move(self.filepath, self.filepath + '.bkup')
        else:
            self.savepath = os.path.realpath(time.strftime(self.saveformat))
        try:
            with open(self.savepath, 'wb') as encfile:
                encfile.write(byteobj)
            if os.path.islink(self.encryptedpath):
                os.unlink(self.encryptedpath)
            os.symlink(self.savepath, self.encryptedpath)
            if os.path.islink(self.revisionpath):
                os.unlink(self.revisionpath)
            os.symlink(self.savepath, self.revisionpath)
        except:
            logger.warning('\nCould not save file!! Trying to revert.\n') # TODO fix better revert
            shutil.move(self.filepath + '.bkup', self.filepath)
            raise
        self.clean_backups()

    def pick_backup_file(self):
        pass

    def get_raw_content(self, filepath=None):
        ''' Sanity check that we have a path and main file to work with. No filepath == latest'''
        if self.initializing:
            return BytesIO()
        self.filepath = filepath
        if not self.filepath: # todo here make it possible to open backups
            if os.path.islink(self.encryptedpath):
                self.filepath = os.readlink(self.encryptedpath)
            else:
                logger.warning('No available file to open!')
                return False
        if os.path.islink(self.encryptedpath):
            logger.info('opening %s', filepath)
            with open(self.filepath, 'rb') as fh:
                byteobj = fh.read()
                logger.debug('Returning read file "%s"', type(byteobj))
                return byteobj
        else:
            # todo glob find old files and open one of them. else initialize
            return self.initial_setup()

    def initial_setup(self, workdir=False, files=False):
        self.initializing = True
        if workdir:
            print('Initializing directory structure')
            logger.info('Creating {0}', WORK_PATH)
            os.mkdir(WORK_PATH, mode=0o700)
            os.chdir(WORK_PATH)

    def backup_first(self):
        if self.initializing:
            return
        self.latest = os.readlink(self.encryptedpath)
        self.bkpname = os.path.realpath(time.strftime('%Y-%m-%d-%H%M%S') + '.bkup')
        self.backedup = False
        try:
            shutil.copy(self.latest, self.bkpname)
            self.backedup = True
            logger.info('Backed up %s to %s', self.latest, self.bkpname)
        except FileNotFoundError as exc:
            logger.warning('1: Failed to create backup copy from {0} to {1}: {2}',\
                    self.latest, self.bkpname, exc)
        except Exception as exc:
            logger.warning('2: Error making backup from {0} to {1}: {2}s\n {3}', self.latest,\
                    self.bkpname, exc, sys.exc_info())
        if os.path.islink(self.encryptedpath) and self.backedup:
            try:
                os.unlink(self.encryptedpath)
                os.symlink(self.bkpname, self.encryptedpath)
            except Exception as exc:
                logger.warning('Failed to link file {0} with {1}: {2}', self.bkpname,\
                        self.encryptedpath, self.encryptedpathexc)

    @property
    def revision_files(self):
        revisions = {}
        revfilelinks = glob(WORK_PATH + os.path.sep + 'revision-' + '*')
        for revfile in revfilelinks:
            revisions[revfile] = os.readlink(revfile)
        return revisions

    def __init__(self, path):
        self.initializing = False
        self.encryptedpath = path
        try:
            os.chdir(WORK_PATH)
        except FileNotFoundError:
            self.initial_setup(workdir=True)
        if len(glob(WORK_PATH + os.path.sep + '*')) < 1:
            self.initializing = True

        logger.debug('initializing = %s', self.initializing)
        #self.backup_first()
        self.backupfiles = glob(WORK_PATH + os.path.sep + '*' + '.enc')
        self.bytecontent =  self.get_raw_content()


#### Filesystem handling END ####

##### Commands #####

entrymockup = ['loginentry1', 'loginentry2', 'loginentry3']
editcmds = ['print', 'password', 'login', 'description']

class MainInterpreter(cmd.Cmd):
    '''An interpreter instance will recognize a
    command name foo if and only if it has a method do_foo(). As a special
    case, a line beginning with the character '?' is dispatched to the method
    do_help(). As another special case, a line beginning with the character '!'
    is dispatched to the method do_shell() (if such a method is defined). '''

    commands = ['add', 'ls', 'edit', 'dump', 'find', 'help', 'rm', 'quit']
    commandsstring = ' '.join(commands).strip()

    def __init__(self, filesys, logins):
        super().__init__()
        self.logins = logins
        self.filesys = filesys
        self.prompt = 'loginmgr:'
        print(self.commandsstring)

    def complete_entries(self, text, line, begidx, endidx):
        if not text:
            completions = self.logins.logins.keys()
        else:
            completions = [f for f in self.logins.logins.keys() if f.startswith(text.strip())]
        return completions

    def do_quit(self, args):
        print('Quitting')

    def do_dump(self, args):
        for name, entry in self.logins.logins.items():
            Logins.loginprinter(entry)

    # ls
    complete_ls = complete_entries

    def do_ls(self, args):
        if args:
            if args in self.logins.logins:
                Logins.loginprinter(self.logins.logins[args])
        else:
            for name in self.logins.logins.keys():
                if not name in filtered_meta:
                    print(name)
    # end ls

    def do_EOF(self, args):
        self.do_quit(args)

    # get
    def do_get(self, args):
        if args:
            if args in self.logins.logins:
                Logins.loginprinter(self.logins.logins[args], pwhide=True, clipboard=True)

    def help_get(self):
        print('"get <name>" (Get a login entry) copy pw to clipboard however do not show it')

    complete_get = complete_entries
    # end get

    # cat
    def do_cat(self, args):
        if args:
            if args in self.logins.logins:
                Logins.loginprinter(self.logins.logins[args], pwhide=False, clipboard=False)

    def help_cat(self):
        print('"cat <name>" (Dump all existing information of a login entry)')

    complete_cat = complete_entries
    # end cat

    # edit
    def do_edit(self, args):
        commander.prompt = "edit(%s)" % args
        self.addoredit(args, edit=True)
        commander.prompt = "loginmgr:"
        return None

    def help_edit(self):
        print('"edit <name>" (Edit the properties of a login entry)')

    complete_edit = complete_entries
    # end edit

    # rm
    def do_rm(self, args):
        yesno = ''
        if args:
            while yesno not in ('y','n'):
                yesno = input('Remove entry %s y/n? ' % args)[0].lower()
            if 'y' in yesno:
                self.logins.remove(args)
        return

    complete_rm = complete_entries
    # end rm

    # search
    def do_search(self, args):
        for entry in self.logins.logins.keys():
            if args in entry:
                print(entry.replace(args, COLORS['red'] + args + '\033[1;m'))
        return

    # add
    def addoredit(self, entry, edit=False):
        self.edit = edit
        self.entry = entry
        if entry in self.logins.logins and not edit:
            logger.warning('Entry for {0} already exist, either edit or remove existing'.format(0))
        elif entry in self.logins.logins and edit:
            logger.info('\nOld entry')
            Logins.loginprinter(self.logins.logins[self.entry])
            self.newlogin = self.logins.logins[self.entry]
            logger.info('\nEdit fields (empty to keep old value)')
            self.editedlogin = input('Login for {0} old:"{1}" :'.format(entry, self.newlogin.get('login', '')))
            self.newlogin['login'] = self.editedlogin or self.newlogin.get('login', '')
            self.editedpassword = input('Password for {0} old:"{1}":'.format(entry, self.newlogin.get('password', '')))
            self.newlogin['password'] = self.editedpassword or self.newlogin.get('password', '')
            while True:
                paramanswer = input('Extra parameter for:{0} (empty to exit):'.format(entry))
                if not paramanswer:
                    break
                else:
                    self.newlogin[paramanswer] = input('Value for {0}:'.format(paramanswer))
        else:
            self.newlogin = {'name': entry}
            self.newlogin['login'] = input('Login for {0}:'.format(entry))
            suggestpass = genpwd(PWLEN)
            newpass = input('Password for "{0}" empty for suggested ({1}):'.format(entry, suggestpass))
            if not newpass:
                newpass = suggestpass
            self.newlogin['password'] = newpass
            while True:
                paramanswer = input('Extra parameter for:{0} (empty to exit):'.format(entry))
                if not paramanswer:
                    break
                else:
                    self.newlogin[paramanswer] = input('Value for {0}:'.format(paramanswer))
        Logins.loginprinter(self.newlogin)
        saveanswer = input('Save entry y/n? ').lower()
        if 'y' in saveanswer or saveanswer == '':
            self.logins.add(self.newlogin, edit=self.edit)
        return

    def do_add(self, args):
        if not args:
            args = input('Name/site for entry?:')
        #commander = AddInterpreter(self.logins, self.filesys, args)
        commander.prompt = "add(%s)" % args
        self.addoredit(args)
        commander.prompt = "loginmgr:"
        return None
        #commander.cmdloop()

    def help_add(self):
        print('"add" Bring you to the login entry add prompt')
    # end add

def commander(filesys, logins):
    try:
        cmdr = MainInterpreter(filesys, logins)
        cmdr.cmdloop()
    except KeyboardInterrupt as e:
        quit(filesys, logins)
        sys.exit()

##### Commands END #####

def main():
    atexit.register(backtodir)
    parseargs()
    filesys = FileSysHandler(FNAME)
    if not filesys.initializing:
        decrypted = decrypt(filesys.get_raw_content())
        logins = Logins(decrypted)
    else:
        logins = Logins(None, initializing=True)

    commander(filesys, logins)
    atexit.register(quit, filesys, logins)
    #signal.signal(1, quit(filesys, logins))
    #signal.signal(2, quit(filesys, logins))
    #signal.signal(signal.SIGINT, quit(filesys, logins))

#    key = Fernet.generate_key()
#    f = Fernet(key)
#    token = f.encrypt(b"my deep dark secret")
#    token
#    print(f.decrypt(token))

if __name__ in '__main__':
    main()
