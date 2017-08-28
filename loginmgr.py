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
COLORS = {'grey': '\033[1;30m', 'red':'\033[1;31m', 'green':'\033[1;32m', 'yellow':'\033[1;33m',\
        'brown':'\033[0;33m', 'blue':'\033[1;34m', 'magenta':'\033[1;35m', 'cyan':'\033[1;36m', 'white':'\033[1;37m', 'stndrd':'\033[0m'}
WORK_PATH = os.path.expanduser("~/.loginmgr")
REVISION_PREFIX = 'revision-'
FNAME = 'loginmgr.crypt'
BKUPNR = 10 # nr of backups to keep
SPECIAL_CHARS = '_!?.&+-'
STARTDIR = os.getcwd()
PWLEN = 21
saltlength = 16
TIMEFORMAT = '%Y-%m-%d %H:%M:%S'
LOGFORMAT = '%(asctime)s %(levelname)s: %(message)s'
LOGFORMATDEBUG = '%(asctime)s %(levelname)s: line:%(lineno)d  func:%(funcName)s;  %(message)s'
filtered_meta_words = ('META', 'SALT', 'old_revisions', 'ctime', 'mtime')


class NoRevisionFound(Exception):
    pass

def parseargs():
    '''
    argument parsing
    '''
    parser = argparse.ArgumentParser(description='Login manager.')
    parser.add_argument('entry', metavar='e', type=str, nargs='*', help='print single entry')
    parser.add_argument('-s' '--setup', dest='setup', action='store_true',\
            default=False, help='Base storage method')
    parser.add_argument('-i' '--import', dest='import',  default=None, help='Import archive (previously exported with "export")')
    parser.add_argument('-d' '--debug', dest='debug', action='store_true',\
            default=False, help='Enable debugging')
    parser.add_argument('-P' '--password-display', dest='pwdisplay', action='store_false',\
            default=True, help='Display passwords on printout of entries (when entries are given as argument)')
    args = parser.parse_args()
    return args

def maxstrlen(maxlenlist):
    return max([len(string) for string in maxlenlist])

def highlight(string, hlsearch):
    string = string.partition(hlsearch)
    return string[0] + COLORS['red'] + string[1] + COLORS['stndrd'] + string[2]

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
    def pre6pwgen(length):
        pwd = ''.join(random.sample(string.ascii_letters * 7 + string.digits * 7 +\
                SPECIAL_CHARS, k=length))[:length]
        return pwd
    def post6pwgen(length):
        return secrets.token_urlsafe(length)
    if sys.version_info[0] == 3 and sys.version_info[1] >= 6: 
        import secrets
        pwdgen = post6pwgen
    else:
        pwdgen = pre6pwgen

    pwd = pwdgen(length)
    while not complexitycheck(pwd):
        pwd = pwdgen(length)
    return pwd

def salter():
    '''Add crap section'''
    return genpwd(200)

def pwpassprompt(decrypt=False):
    '''Prompt for password'''
    try:
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
    except KeyboardInterrupt:
        print('\nNo changes saved! Old password is in effect!\nBye!')
        sys.exit(0)
    return str.encode(pass1)

def enryption_tokenizer(encpassbase, salt=None):
    '''
    >>> enryption_tokenizer() #doctest: +ELLIPSIS
    <cryptography.fernet.Fernet object...
    '''
    if not salt:
        if sys.version_info[0] == 3 and sys.version_info[1] >= 6: 
            import secrets
            salt = secrets.token_bytes(saltlength)
        else:
            salt = os.urandom(saltlength)
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
        return decryptedbytes
    except TypeError:
        logger.critical('Failed to decrypt content, content corrupted?!?!')
        #todo implement recovery (suggestions and action)
        raise
    except InvalidToken:
        logger.warning('Wrong password')
        return None

def decrypter(byteobj):
    decryptedbytes = decrypt(byteobj)
    while not decryptedbytes:
        decryptedbytes = decrypt(byteobj)
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

def rev_from_filename(filename):
    try:
        filename = os.path.basename(filename)
        filenamepart = filename.strip('loginmgr-rev-') 
        revision = filenamepart.partition('--')[0]
        logger.debug('Revision extracted from filename {}'.format(revision))
    except Exception as exc:
        print('Failed to extract revision from filename {exc}'.format(exc))
        return False
    return revision

def backup_export(filesys, logins):
    '''Tar / zip and point to full backup of dir'''
    saveformat = 'loginmgr-rev-{}--%Y-%m-%d-%H%M%S.backup'.format(logins.newrevision)
    bkupfilename = time.strftime(saveformat)
    try:
        shutil.make_archive(bkupfilename, 'gztar', verbose=1, logger=logger)
        print('Created backup: {}'.format(os.path.realpath(bkupfilename + '.tar.gz')))
    except Exception as exc:
        logger.warning('Failed to create archive / export {}'.format(exc))
        return False

def import_restore(archivefile, filesys):
    '''Untar / Unzip and restore to work path'''
    archivefile = os.path.realpath(archivefile)
    backupextension = '-%Y-%m-%d-%H%M%S.backup'
    bkupdirname = time.strftime(backupextension)
    restorepath = WORK_PATH + '-restore'
    if os.path.isdir(restorepath):
        logger.debug('Removing old restore point')
        shutil.rmtree(restorepath)
    if not filesys.initializing:
        # if we import into an emty dir the there is no worry
        importrevision = int(rev_from_filename(archivefile))
        latestcurrentrevision = int(sorted([int(rev) for rev in filesys.revisions.keys()])[-1])
        logger.debug('latestcurrentrevision: {}'.format(latestcurrentrevision))
        if importrevision <= latestcurrentrevision:
            print('Warning the import contains revision:"{}" and your latest revision is:"{}"\
                    this could lead to loss of data'.format(importrevision, latestcurrentrevision))
            yesno = input('Do you want to continue the import and potentially loose data!? (Yes/No):')
            if 'y' in yesno.lower():
                pass
            else:
                print('Cancelling!')
                sys.exit(0)
    if not os.path.isfile(archivefile):
        logger.warning('Import archive "{}" not available'.format(archivefile))
        return None
    try:
        logger.debug('Moving {0} to {1}'.format(WORK_PATH, WORK_PATH + bkupdirname))
        shutil.move(WORK_PATH, WORK_PATH + bkupdirname)
        os.mkdir(restorepath, mode=0o700)
        os.chdir(restorepath)
        logger.info('Importing / restoring {}'.format(archivefile))
        shutil.unpack_archive(archivefile)
        if not os.path.islink(os.path.join(restorepath, FNAME)):
            logger.warning('Failed to restore archive ( archive does not contain a: "{}" )!! Restoring old dir'.format(FNAME))
            shutil.rmtree(restorepath)
            shutil.move(WORK_PATH + bkupdirname, WORK_PATH)
    except Exception as exc:
        logger.warning('Failed to create archive / export {}'.format(exc))
        return False
    shutil.move(restorepath, WORK_PATH)
    print('Restored loginmgr from archive')
    shutil.rmtree(WORK_PATH + bkupdirname)

def to_clipboard(text):
    try:
        xclipper = subprocess.Popen(['xclip', '-selection', 'c'], stdin=subprocess.PIPE, close_fds=True)
    except FileNotFoundError:
        logger.warning('Failed to copy password to clipboard (need "xclip" application)')
    _, stderr = xclipper.communicate(text.encode('utf-8'))
    if xclipper.returncode != 0:
        logger.warning('Failed to copy password to clipboard:', stderr)

def quit(filesys, logins, save=True, export=False):
    logger.debug('Quitting with logins: {0}, filesys: {1}'.format(logins, filesys))
    print()
    if not save:
        sys.exit(0)
    encryptedbytes = encrypt(logins.save())
    filesys.feedandsave(encryptedbytes, logins)
    if export:
        backup_export(filesys, logins)
    sys.exit(0)

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
            self.deleted.append(login)
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
            login['ctime'] = time.strftime(TIMEFORMAT)
        if edit:
            # Some info so that we can retreive last editions
            login['mtime'] = time.strftime(TIMEFORMAT)
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
        if edit: # we only change revision on edit and remove
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
        self.logins['META']['deleted'].append((name, self.revision))
        logger.warning('Logins can be restored from older revisions\
                (i.e history files use revls of search to find\
                deleted entries)! You can then open and retreive\
                them using revopen')
        logger.warning('Removed login %s', name)
        return True

    def loginprinter(login, pwhide=True, clipboard=False, filtermeta=True):
        printfirstkeys = ('name', 'login', 'password')
        print('\n{0}:'.format(login['name']))
        maxlen = str(maxstrlen(login.keys()))
        printrest = [key for key in login.keys() if key not in printfirstkeys]
        printlist = []

        for key, val in login.items():
            strformat = '{0:<' + maxlen + '} : {1}'
            if filtermeta and key in filtered_meta_words:
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
        print()


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
        self.deleted = []
        self.edited = []
        self.added = []
        if initializing:
            self.logins = {}
            self.revision = 1
            self.newrevision = 1
            firstlogin = self.add({'name': 'META', 'password': 'META', 'login': 'META', 'revision': self.revision, 'deleted': [] } )
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
            for backupfile in self.cleanbkups:
                logger.info('Cleaning old backup file: %s' % backupfile)
                os.remove(backupfile)
                for backuplink in glob(REVISION_PREFIX + '*'):
                    if os.path.basename(os.readlink(backuplink)) == os.path.basename(backupfile):
                        os.remove(backuplink)
                        logger.info('Cleaning old revision: %s' % backuplink)
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
        self.revisionpath = os.path.join(WORK_PATH, 'revision-' + str(logins.newrevision))
        if logins.newrevision == logins.revision and not self.initializing:
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
            self.filepath = os.path.join(WORK_PATH, FNAME)
            return BytesIO()
        self.filepath = filepath
        if not self.filepath: # todo here make it possible to open backups
            if os.path.islink(self.encryptedpath):
                self.filepath = os.readlink(self.encryptedpath)
            else:
                logger.warning('No available file to open!')
                return False
        if os.path.islink(self.encryptedpath):
            logger.info('opening %s', self.filepath)
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
    def revisions(self):
        revisionlist = {}
        revfilelinks = glob(WORK_PATH + os.path.sep + 'revision-' + '*')
        for revfile in revfilelinks:
            revnr = os.path.basename(revfile).strip('revision-') 
            revisionlist[revnr] = os.readlink(revfile)
        logger.debug('Revisionlist: {}'.format(str(revisionlist)))
        return revisionlist

    def revisiongetter(revisionnr):
        '''Takes an int and returns a path to use'''
        revision = WORK_PATH + os.path.sep + REVISION_PREFIX + str(revisionnr)
        if not os.path.islink(revision):
            logger.warning('Failed to find file for revision:', revisionnr )
            return None
        return os.path.basename(revision)

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
    intro = 'Welcome to loginmgr shell. Type help or ? to list commands.\n'

    def __init__(self, filesys, logins):
        super().__init__()
        self.logins = logins
        self.filesys = filesys
        self.prompt = 'loginmgr:'
        self.save = True
        self.do_help('')

    def complete_entries(self, text, line, begidx, endidx):
        if not text:
            completions = self.logins.logins.keys()
        else:
            completions = [f for f in self.logins.logins.keys() if f.startswith(text.strip())]
        return completions

    # quit
    def do_quit(self, args):
        print('Quitting' + ' and saving!' if self.save else ' without saving!')
        quit(self.filesys, self.logins, self.save)

    def help_quit(self):
        print('"quit" quit, encrypt and save. If there was changes a new revision will be saved and the oldest one rotated out')

    do_q = do_quit
    help_q = help_quit
    # end quit

    def do_dump(self, args):
        for name, entry in self.logins.logins.items():
            Logins.loginprinter(entry, pwhide=True, clipboard=False, filtermeta=False)
            print()

    def help_dump(self):
        print('"dump" dump everything')

    # ls
    complete_ls = complete_entries

    def do_ls(self, args):
        if args:
            if args in self.logins.logins:
                Logins.loginprinter(self.logins.logins[args])
        else:
            for name in self.logins.logins.keys():
                if not name in filtered_meta_words:
                    print(name)

    def help_ls(self):
        print('"ls <text> | ls " list all entries names (no argument) or if specified list details of one specific')
    # end ls

    # search
    def do_search(self, args):
        '''Search all logins for a match, and inside all key/values (except password) for a match too'''
        searchresults = []
        args = args.lower()
        for entry in self.logins.logins.keys():
            if entry in filtered_meta_words:
                continue
            if args in entry:
                print(entry)
            for key, val in self.logins.logins[entry].items():
                if key == 'password':
                    continue
                if args in str(key).lower():
                    print("{0} : {1} : {2}".format(entry, highlight(key, args), val))
                if args in str(val).lower():
                    print("{0} : {1} : {2}".format(entry, key, highlight(val, args)))

        for login in self.logins.logins['META']['deleted']:
            if args in login[0]:
                print(('{0} : (revision {1})' + COLORS['red'] + ' (deleted)' + COLORS['stndrd']).format(highlight(login[0], args), login[1]))
        return

    def help_search(self):
        print('"search <text>" Search all logins for a match, and inside all key/values for a match too')
    # end search

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
                Logins.loginprinter(self.logins.logins[args], pwhide=False, clipboard=False, filtermeta=False)

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
                yesno = input('Really sure you want to remove %s y/n? ' % args)[0].lower()
                if 'y' in yesno:
                    self.logins.remove(args)
        return

    def help_rm(self):
        print('"rm <name>" (Remove the properties of a login entry)')

    complete_rm = complete_entries
    # end rm

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

    # revls
    def do_revls(self, args):
        for rev in self.filesys.revisions:
            print(rev)
        print( COLORS['red'] + 'Deleted entries:' + COLORS['stndrd'])
        for login in self.logins.logins['META']['deleted']:
            print('{0} : (revision {1})'.format(login[0], login[1]))

    def help_revls(self):
        print('"revls" list available revisions, and deleted entries')
    # end revls

    # revopen
    def do_revopen(self, args):
        revfile = FileSysHandler.revisiongetter(args)
        if not revfile:
            return None
        self.filesys = FileSysHandler(revfile)
        self.logins = Logins(decrypter(self.filesys.get_raw_content()))
        self.oldrevision = True
        self.save = False
        print('Saving will be disabled when working on old revision.\
                Retreive what is needed and copy and save in the latest revision manueally.')
        return 

    def help_revopen(self):
        print('"revopen <nr>" open available revision (read only)\nPassword that was used to encrypt that revision must be provided (maybe not the same as for the current one)')
    # end revopen

    # export / backup
    def do_export(self, args):
        quit(self.filesys, self.logins, save=self.save, export=True )

    def help_export(self, args):
        print('Will create a full backup of all data. Should be able to unpack to $HOME/.loginmgr. Or use import on a new install. Import will of course overwrite all previous data. So be careful')

    do_backup = do_export
    help_backup = help_export
    # end export / backup

def commander(filesys, logins):
    '''Main command interpreter'''
    try:
        cmdr = MainInterpreter(filesys, logins)
        cmdr.cmdloop()
    except KeyboardInterrupt as e:
        quit(filesys, logins, cmdr.save)
        sys.exit()

##### Commands END #####

def entryprint(logins, entryargs):
    '''Print one entry that begins with the string provided on cli and exit'''
    entries = [f for f in logins.logins.keys() if f.startswith(entryargs[0].strip())]
    for entry in entries:
        Logins.loginprinter(logins.logins[entry], pwhide=args.pwdisplay, clipboard=True)
        print()
    sys.exit(0)

def main():
    atexit.register(backtodir)
    filesys = FileSysHandler(FNAME)

    if getattr(args, 'import') is not None:
        import_restore(getattr(args, 'import'), filesys)
        del filesys
        filesys = FileSysHandler(FNAME)

    if not filesys.initializing:
        decrypted = decrypter(filesys.get_raw_content())
        logins = Logins(decrypted)
    else:
        logins = Logins(None, initializing=True)
    print('Revision {0[revision]}'.format(logins.logins['META']))
    print('{} entries'.format(len(logins.logins) - 2))

    if args.entry:
        entryprint(logins, args.entry)

    commander(filesys, logins)
    atexit.register(quit, filesys, logins, logins.save)

if __name__ in '__main__':
    args = parseargs()
    loginmgrlogger = logging.StreamHandler(stream=sys.stderr)
    logger = logging.getLogger("loginmgr")
    logger.addHandler(loginmgrlogger)

    if args.debug:
        dbgformatter = logging.Formatter(LOGFORMATDEBUG)
        logger.setLevel(logging.DEBUG)
        loginmgrlogger.setFormatter(dbgformatter)
        logger.debug('Debugging enabled')
    else:
        formatter = logging.Formatter(LOGFORMAT)
        loginmgrlogger.setFormatter(formatter)
        logger.setLevel(logging.INFO)
    logger.debug('Cli arguments: %s', args)
    main()
