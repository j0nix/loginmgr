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
WORK_PATH = '/home/carl/Code/loginmgr/TEST'
FNAME = 'testfile.crypt'
BKUPNR = 10 # nr of backups to keep
SPECIAL_CHARS = '_!?.&+-'
STARTDIR = os.getcwd()
saltlength = 16
LOGFORMAT = '%(asctime)s %(levelname)s: %(message)s'
LOGFORMATDEBUG = '%(asctime)s %(levelname)s: line:%(lineno)d  func:%(funcName)s;  %(message)s'
logger = logging.getLogger('loginmgr')
COLORS = {'grey': '\033[1;30m', 'red':'\033[1;31m', 'green':'\033[1;32m', 'yellow':'\033[1;33m',\
        'brown':'\033[0;33m', 'blue':'\033[1;34m', 'magenta':'\033[1;35m', 'cyan':'\033[1;36m', 'white':'\033[1;37m', 'stndrd':'\033[0m'}

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
    filesys.feedandsave(encryptedbytes, logins.revision)

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

    def setupdated(self, edit, login):
        self.changed = True
        if self.revision == self.newrevision:
            self.newrevision = self.revision + 1
        if edit:
            self.edited.append(login)
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
            login['mtime'] = time.time()
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
        self.setupdated(edit, login)

    def edit(self, config={}):
        self.add(config={}, edit=True)

    def remove(self, name):
        try:
            logins.pop(name)
        except KeyError:
            logger.warning('%s is not a configured login', name)
        self.setupdated()

    def loginprinter(login):
        print(login)
        print('{0}:'.format(login['name']))
        maxlen = str(maxstrlen(login.keys()))
        for key, val in login.items():
            strformat = '{0:<' + maxlen + '} : {1}'
            if 'login' in key:
                strformat = COLORS['green'] + strformat + '\033[1;m'
            if 'password' in key:
                strformat = COLORS['red'] + strformat + '\033[1;m'
            if 'name' in key:
                strformat = COLORS['blue'] + strformat + '\033[1;m'
            print(strformat.format(key, val))

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

    def feedandsave(self, byteobj, revision):
        '''takes in the content (likely encrypted bytes) and saves it as the
        newest save that means that it has to be different than what was opened
        first.
        >>> feedandsave(self, b'abc123')
        '''
        try:
            self.savepath = os.path.realpath(time.strftime(self.saveformat))
            self.revisionpath = os.path.realpath('revision-' + str(revision))
            with open(self.savepath, 'wb') as encfile:
                encfile.write(byteobj)
            if os.path.islink(self.encryptedpath):
                os.unlink(self.encryptedpath)
            os.symlink(self.savepath, self.encryptedpath)
            os.symlink(self.savepath, self.revisionpath)
        except:
            logger.warning('Could not save file')
            raise
        self.clean_backups()

    def pick_backup_file(self):
        pass

    def get_raw_content(self, filepath=None):
        ''' Sanity check that we have a path and main file to work with. No filepath == latest'''
        if self.initializing:
            return BytesIO()
        if not filepath:
            if os.path.islink(self.encryptedpath):
                filepath = os.readlink(self.encryptedpath)
            else:
                logger.warning('No available file to open!')
                return False
        if os.path.islink(self.encryptedpath):
            logger.info('opening %s', filepath)
            with open(filepath, 'rb') as fh:
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

commands = ['print', 'dump', 'edit', 'find', 'help', 'add', 'delete', 'quit', 'save']
entrymockup = ['loginentry1', 'loginentry2', 'loginentry3']
editcmds = ['print', 'password', 'login', 'description']

class MainInterpreter(cmd.Cmd):
    '''An interpreter instance will recognize a
    command name foo if and only if it has a method do_foo(). As a special
    case, a line beginning with the character '?' is dispatched to the method
    do_help(). As another special case, a line beginning with the character '!'
    is dispatched to the method do_shell() (if such a method is defined). '''

    def __init__(self, filesys, logins):
        super().__init__()
        self.logins = logins
        self.filesys = filesys

    def do_quit(self, args):
        print('Quitting')

    def do_dump(self, args):
        for name, entry in self.logins.logins.items():
            Logins.loginprinter(entry)

    def do_EOF(self, args):
        self.do_quit(args)

    def do_edit(self, args):
        #print('edit Login entry')
        if args:
            commander = AddInterpreter(self.logins, self.filesys, args, edit=True)
            commander.prompt = "edit(%s)" % args
            commander.cmdloop()

    def help_edit(self):
        print('"edit <name>" (Edit the properties of a login entry)')

    def complete_edit(self, text, line, begidx, endidx):
        if not text:
            completions = entrymockup
        else:
            completions = [f for f in entrymockup if f.startswith(text.strip())]
        return completions

    def do_add(self, args):
        if not args:
            args = input('Name/site for login entry?:')
        commander = AddInterpreter(self.logins, self.filesys, args)
        commander.prompt = "add(%s)" % args
        commander.cmdloop()

    def help_add(self):
        print('"add" Bring you to the login entry add prompt')


class AddInterpreter(cmd.Cmd):
    def __init__(self, logins, filesys, entry, edit=False):
        super().__init__()
        self.edit = edit
        self.logins = logins
        self.filesys = logins
        self.entry = entry
        if entry in self.logins.logins and not edit:
            logger.warning('Entry for {0} already exist, either edit or remove existing'.format(0))
        elif entry in self.logins.logins and edit:
            logger.info('\nOld entry')
            Logins.loginprinter(self.logins.logins[self.entry])
            self.newlogin = logins.logins[self.entry]
            logger.info('\nEdit fields (empty to keep old value)')
            self.newlogin['login'] = input('Login for {0} old:"{1}" :'.format(entry, self.newlogin['login']))
            self.newlogin['password'] = input('Password for {0} old:"{1}":'.format(entry, self.newlogin['password']))
        else:
            self.newlogin = {'name': entry}
            self.newlogin['login'] = input('Login for {0}:'.format(entry))
            self.newlogin['password'] = input('Password for {0}:'.format(entry))
        self.do_print(self.entry)

    def do_EOF(self, args):
        answer = ''
        Logins.loginprinter(self.newlogin)
        while answer not in ('y','n'):
            answer = input('Save entry y/n? ')[0].lower() 
        if 'y' in answer:
            self.logins.add(self.newlogin, edit=self.edit)
            return True
            #commander(self.logins, self.filesys)
        else:
            return True
            #csommander(self.logins, self.filesys)

    def help_print(self):
        print('print current Login entry')

    def do_print(self, args):
        Logins.loginprinter(self.newlogin)
        

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
