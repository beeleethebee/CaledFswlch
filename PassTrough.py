#!/usr/bin/env python3
# coding=utf-8

from __future__ import with_statement

import os
import sys
import errno
import argparse

from fuse import FUSE, FuseOSError, Operations
from shutil import rmtree

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from EncrDecr import DebateME
import colours


class Passthrough(Operations):
    def __init__(self, root, password):
        if root[-1] != '/':
            root += '/'
        self.root = root
        self.password = Fernet(DebateME().encode_key(password))
        self.isCorrupt()

    # Helpers
    # =======

    def _full_path(self, partial):
        """ Return le path envoyé en paramètre en fonction de l'emplacement du dossier crypté """
        if partial.startswith("/"):
            partial = partial[1:]
        path = os.path.join(self.root, partial)
        # print("On passe de " + partial + " a " + path)
        return path

    def translation_machine_user(self, content):
        """ Decrypt des données par rapport à la clé password """
        return self.password.decrypt(content)

    def translation_user_machine(self, content):
        """ Encrypt des données par rapport à la clé password """
        return self.password.encrypt(content.encode())

    #TODO  # in dev
    def translation_path_machine_user(self, crypted_path):
        """ Decrypt de manière iterative le chemin passe en argument en chemin crypte / par /"""
        splited_path = crypted_path[len(self.root):].split('/')
        return_path = self.root
        for i in range(0, len(splited_path)):
            try:
                ep = self.translation_machine_user(splited_path[i].encode()).decode()
                return_path += ep + '/' if i < len(splited_path) - 1 else ep
            except:
                pass
        return return_path

    #TODO  # in dev
    def translation_path_user_machine(self, uncrypted_path):
        """  Enecrypt de manière iterative le chemin passe en argument en chemin encrypte / par /"""
        splited_path = uncrypted_path.split('/')
        return_path = self.root
        for i in range(0, len(splited_path)):
            try:
                ep = self.translation_user_machine(splited_path[i]).decode()
                return_path += ep + '/' if i < len(splited_path) - 1 else ep
            except:
                pass
        return return_path

    def isCorrupt(self):
        """ Verification de la clef de crpytage : en mettant un fichier avec une valeur connue, on verifie si on
        obtient la même valeur au decryptage qu'a l'initialisation """
        corrupt_path = self.root + ".CaledSwlch"
        advertise_string = self.translation_user_machine('Attention ne surtout pas modifier ce fichier sous peine '
                                                         'd\'une corruption et la perte de vos donnees')
        if not os.path.exists(corrupt_path):
            corrupt_file = open(corrupt_path, 'wb')
            corrupt_file.write(advertise_string)

            print(colours.colour[
                      "red"] + "Création du fichier .CaledSwlch dans " + self.root + ", attention a ne pas le toucher" +
                  colours.colour["default"])
        else:
            corrupt_file = open(corrupt_path, 'rb')
            try:
                content = self.translation_machine_user(corrupt_file.readline()).decode()
                advertise_string == self.translation_machine_user(advertise_string).decode()
            except:
                print(colours.colour[
                          "red"] + "Il semble que le mot de passe est mauvais: les fichier sont corrompus, vueillez à entrer le mdp" +
                      colours.colour["default"])
                exit(1)
        corrupt_file.close()

    # Filesystem methods
    # ==================

    def access(self, path, mode):
        """ Override de la methode access
        Le comportement de cette méthode reste inchangé
        Permet de tester les droits sur le fichier/dossier ciblé en fonction de uid/gid
        """

        full_path = self._full_path(path)
        # print('methode access pour ', full_path)
        if not os.access(full_path, mode):
            raise FuseOSError(errno.EACCES)

    def chmod(self, path, mode):
        """ Override de la methode chmod
        Le comportement de cette méthode reste inchangé
        Permet de modifier le mode d'un dossier/fichier ciblé
        """

        # print('methode chmod sur ', path)
        full_path = self._full_path(path)
        return os.chmod(full_path, mode)

    def chown(self, path, uid, gid):
        """ Override de la methode chown
        Le comportement de cette méthode reste inchangé
        Permet de modifier le uid/gid d'un fichier/dossier ciblé
        """

        full_path = self._full_path(path)
        # print('methode chown pour ', path)
        return os.chown(full_path, uid, gid)

    def getattr(self, path, fh=None):
        """ Override de la methode getattr
        Le comportement de cette méthode reste inchangé
        return un dictionnaire contenant les Metadata d'un dossier/fichier ciblé
        """

        full_path = self._full_path(path)
        st = os.lstat(full_path)
        # print('methode getattr pour ', path)
        return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                                                        'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size',
                                                        'st_uid'))

    def readdir(self, path, fh):
        """ Override de la methode readdir
        Le comportement de cette méthode reste inchangé
        Permet de lire le nom des fichiers/dossiers contenu dans le dossier ciblé
        """

        full_path = self._full_path(path)
        dirents = ['.', '..']
        # print('methode readdir pour ', path)
        if os.path.isdir(full_path):
            dirents.extend(os.listdir(full_path))
        for r in dirents:
            yield r

    def readlink(self, path):
        """ Override de la methode readlink
        Le comportement de cette méthode reste inchangé
        Permet de return le fichier/dossier sur lequel pointe un fichier symbolique
        """

        pathname = os.readlink(self._full_path(path))
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.root)
        else:
            return pathname

    def mknod(self, path, mode, dev):
        """ Override de la methode mkmod
        Le comportement de cette méthode reste inchangé
        Permet de créer un fichier system noeud
        """

        return os.mknod(self._full_path(path), mode, dev)

    def rmdir(self, path):
        """ Override de la methode rmdir
        Le comportement de cette méthode reste inchangé
        Permet de supprimé un dossier vide
        """

        full_path = self._full_path(path)
        return os.rmdir(full_path)

    def mkdir(self, path, mode):
        """ Override de la methode mkdir
        Le comportement de cette méthode reste inchangé
        Permet de créer un dossier
        """

        # print('methode mkdir pour ', path)
        return os.mkdir(self._full_path(path), mode)

    def statfs(self, path):
        """ Override de la methode statfs
        Le comportement de cette méthode reste inchangé
        Return un dictionnaire contenant les information du filseystem ciblé
        """

        # print('methode statfs pour ', path)
        full_path = self._full_path(path)
        stv = os.statvfs(full_path)
        return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
                                                         'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files',
                                                         'f_flag',
                                                         'f_frsize', 'f_namemax'))

    def unlink(self, path):
        """ Override de la methode unlink
        Le comportement de cette méthode reste inchangé
        Permet de supprimer le chemin vers le fichier ciblé
        """

        return os.unlink(self._full_path(path))

    def symlink(self, name, target):
        """ Override de la methode symlink
        Le comportement de cette méthode reste inchangé
        Permet de créer un lien symbolique vers target
        """

        return os.symlink(target, self._full_path(name))

    def rename(self, old, new):
        """ Override de la methode rename
        Le comportement de cette méthode reste inchangé
        Permet de modifié le nom d'un fichier/dossier
        """
        # print('methode rename')
        return os.rename(self._full_path(old), self._full_path(new))

    def link(self, target, name):
        """ Override de la methode link
        Le comportement de cette méthode reste inchangé
        Permet de créer un Hard link vers target
        """

        return os.link(self._full_path(name), self._full_path(target))

    def utimens(self, path, times=None):
        """ Override de la methode utimens
        Le comportement de cette méthode reste inchangé
        Permet de modifié le atime/mtime
        """

        return os.utime(self._full_path(path), times)

    # File methods
    # ============

    def open(self, path, flags):
        """ Override de la methode open
        Le comportement de cette méthode reste inchangé
        return le file handler du fichier ciblé
        """

        # print('methode open pour ', path)
        full_path = self._full_path(path)
        return os.open(full_path, flags)

    def create(self, path, mode, fi=None):
        """ Override de la methode create
        Le comportement de cette méthode reste inchangé
        Return le file handler du fichier créer
        """

        # print('methode create pour ', path)
        full_path = self._full_path(path)
        return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    def read(self, path, length, offset, fh):
        """ Override de la File Method read
        Toutes les données son décryptées avant d'être return
        Return une string contenant les informations lues
        """

        # print('methode read pour ', path)
        os.lseek(fh, offset, os.SEEK_SET)
        # Try car si le fichier est vide il y a un soucis.
        try:
            return self.translation_machine_user(os.read(fh, length))
        except BaseException:
            return ""

    def write(self, path, buf, offset, fh):
        """ Override de la File Méthod write
        Toutes les données sont cyptées avant d'être écrites à l'aide de la fonction os.write
        Le fichier est toujours vidé avant l'écriture afin d'éviter les erreurs d'offset
        Return le nombre de byte écrit
        """
        lenbuf = len(buf)
        file = open("root" + path, "rb")
        file_data = file.read()
        if len(file_data) > 0:
            file_data = self.translation_machine_user(file_data)
        new_data = file_data + buf
        os.lseek(fh, offset, os.SEEK_SET)
        buf = self.password.encrypt(new_data)
        os.ftruncate(fh, 0)
        bite = os.write(fh, buf)
        return lenbuf

    def truncate(self, path, length, fh=None):
        """ Override de la methode truncate
        Le comportement de cette méthode reste inchangé
        Truncate le fichier jusqu'a la longeur length
        """

        full_path = self._full_path(path)
        with open(full_path, 'r+') as f:
            f.truncate(length)

    def flush(self, path, fh):
        """ Override de la methode flush
        Le comportement de cette méthode reste inchangé
        Force l'écriture dans un fichier
        """
        return os.fsync(fh)

    def release(self, path, fh):
        """ Override de la methode release
        Le comportement de cette méthode reste inchangé
        Ferme le fichier associé au file handler
        """

        return os.close(fh)

    def fsync(self, path, fdatasync, fh):
        """ Override de la methode fsync
        Le comportement de cette méthode reste inchangé
        Appel la méthode flush
        """

        return self.flush(path, fh)

    # Methodes cryptrages


def findHomeName():
    """ Retrouver le usernam en fonction de son dossier home """
    homedir = os.environ['HOME']
    i = len(homedir) - 1
    j = 0
    while i > 0:
        if homedir[i] != "/":
            j += 1
        elif homedir[i] == "/":
            break
        i -= 1
    return homedir[len(homedir) - j:]


def main(mountpoint=None, root=None, password=None):
    if root and mountpoint:
        print("Décryptage de " + root + " dans " + mountpoint)
        try:
            FUSE(Passthrough(root, password), mountpoint, nothreads=True, foreground=True)
        except RuntimeError:
            print(colours.colour[
                      "blue"] + "Veuillez fermez d'abord caledfswlch d'abord avec la commande : ./close.py" +
                  colours.colour["default"])
            exit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=str)
    parser.add_argument("-m", "--mountpoint")
    parser.add_argument("-p", "--password")
    parser.add_argument("-b", action="store_true")
    parser.add_argument("-d", action="store_true")
    args = parser.parse_args()

    password = args.password if args.password else findHomeName()
    main(args.mountpoint, root=args.root, password=password)
    if args.d:
        rmtree(args.mountpoint)
