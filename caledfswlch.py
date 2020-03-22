#!/usr/bin/env python3

import argparse
import errno
import os
from shutil import rmtree

import colours

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('root', nargs='?', type=str, help="Dossier à décrypter")
    parser.add_argument("-m", "--mountpoint",
                        help="Dosier où vont se retrouver tous les fichiers décryptés 'coffre/' par défaut")
    parser.add_argument("-p", "--password", help="Entrez votre mot de passe")
    parser.add_argument("-b", help="Lance en fond de tâche", action="store_true")
    parser.add_argument("-d", help="Supprime le mountpoint après utilisation", action="store_true")
    args = parser.parse_args()

    if args.root:
        try:
            os.mkdir(args.root)
            if not os.path.isdir(args.root):
                print("Veillez à bien séléctionner un dossier")
                exit(1)
            print("Création du dossier crypté :  " + args.root)
        except:
            print("Utilisation de " + args.root + " comme dossier crypté")

    else:
        args.root = "./root"
        try:
            os.mkdir('./root')
            print("Création du dossier ./root ...")
            print(colours.colour[
                      "blue"] + "La prochaine fois que vous executez la commande veillez à bien préciser ./root pour retrouver vos données " +
                  colours.colour["default"])
        except OSError:
            print("Dossier './root détecté dans le repertoire courant")

    if args.b:
        print(colours.colour["red"] + "Pour quitter le mode background, executez : ./close.py" + colours.colour[
            "default"])

    if args.mountpoint is None or not os.path.isdir(args.mountpoint):
        if args.mountpoint is None:
            args.mountpoint = "./mountpoint"

        if not os.path.exists(args.mountpoint):
            os.mkdir(args.mountpoint)
            print((colours.colour[
                       "green"] + "Création du point de montage pour " + args.mountpoint) +
                  colours.colour["default"])

    if len(os.listdir(args.mountpoint)) > 0:
        print("Point de montage non vide pour " + args.mountpoint)
        while "la réponse n'est pas bonne ":
            answer = str(input("Vider le contenu du dossier ? (Any Key = yes / n = no) : "))
            if answer == "n":
                print(colours.colour[
                          "blue"] + "Revenez lorsque le dossier " + args.mountpoint + " sera vide." +
                      colours.colour["default"])
                exit(1)
            else:
                break
        print("Suppression totale du dossier " + args.mountpoint)
        rmtree(args.mountpoint)
        print("Création du point de montage pour " + args.mountpoint)
        os.mkdir(args.mountpoint)

    os.system('./PassTrough.py ' + args.root + " " + # todo : trouver le fichier tout seul sans se baser sur le dossier recurent
              ((" -p " + args.password) if args.password else " ") +
              ((" -m " + args.mountpoint) if args.mountpoint else " ") +
              (" -d " if args.d else " ") +
              (" &" if args.b else " "))
