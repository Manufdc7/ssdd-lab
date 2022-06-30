#!/usr/bin/env python3
"""Module containing a template for a main service."""

#pylint: disable=no-member, invalid-name, unused-argument, import-error, wrong-import-position, logging-format-interpolation

import logging
from pickle import NONE
import uuid
import sys
from threading import Lock, Timer
import Ice
import IceStorm
import json
import os
import logging
from secrets import token_urlsafe
from random import choice
from service_announcement import (
    ServiceAnnouncementsListener,
    ServiceAnnouncementsSender,
)

try:
    import IceFlix
except ImportError:
    Ice.loadSlice(os.path.join(os.path.dirname(__file__), "iceflix.ice"))
    import IceFlix  

logging.getLogger().setLevel(logging.DEBUG)


def read_file_contents(file_name):
    """Lee los usuarios y devuelve un diccionario. Usado por la interfaz de los canales de eventos
    y Authenticator"""
    data = {}
    with open(file_name, "r", encoding="utf-8") as file:
        if os.stat("users.json").st_size != 0:
            data = json.load(file)
    return data

def write_file(file_name, contents):
    """Escribe en un archivo. Usado la interfaz de los canales de eventos y Authenticator"""
    with open(file_name, "w", encoding="utf-8") as file:
        json.dump(contents, file)


class UsersDB_I(IceFlix.UsersDB):
    """Estructura formada por los usuarios y el hash de sus respectivas contraseñas"""
    def __init__(self, user_passwords, users_token):
        self.userPasswords = user_passwords
        self.usersToken = users_token


class UserUpdatesI(IceFlix.UserUpdates):
    """Implementación del canal de eventos de actualización de usuarios o tokens.
    Cuando recibe una llamada se comprueba que no se haya envíado a sí mismo para no añadir
    un token o usuario dos veces"""
    def __init__(self, auth_service):
        self.auth_service = auth_service

    def newUser(self, user, pass_hash, srv_id, current=None):
        """Evento de nuevo usuario"""
        logging.info("New user event received")
        if srv_id != self.auth_service.service_id and srv_id in self.auth_service.announcement_sub.authenticators:
            logging.info(f"New user {user} added to database")
            data = read_file_contents("users.json")

            if not data.get(user):
                data[user] = pass_hash
                write_file("users.json", data)

    def newToken(self, user, token, srv_id, current=None):
        """Evento de nuevo token"""
        logging.info("New token event received")
        if srv_id != self.auth_service.service_id and srv_id in self.auth_service.announcement_sub.authenticators:
            logging.info(f"New token {token} for user {user} added to database")
            self.auth_service.tokens[token] = user


class RevocationsI(IceFlix.Revocations):
    """Implementación del canal de eventos de revocación de usuarios y tokens.
    Cuando recibe una llamada se comprueba que no se haya envíado a sí mismo para no eliminar
    un token o usuario dos veces"""
    def __init__(self, auth_service):
        self.auth_service = auth_service

    def revokeToken(self, token, srv_id, current=None):
        """Se elimina el token"""
        logging.info("Revoked token event received")
        if srv_id != self.auth_service.service_id and srv_id in self.auth_service.announcement_sub.authenticators and token in self.auth_service.tokens:
            logging.info(f"Token {token} has been deleted")
            self.auth_service.tokens.pop(token)

    def revokeUser(self, user, srv_id, current=None):
        """Se elimina el usuario"""
        logging.info("Revoked user event received")
        if srv_id != self.auth_service.service_id and srv_id in self.auth_service.announcement_sub.authenticators:
            logging.info(f"User {user} has been deleted")
            data = read_file_contents("users.json")

            if data.get(user):
                data.pop(user)
                write_file("users.json", data)


class AuthenticatorI(IceFlix.Authenticator):
    """Implementación de la interfaz Authenticator del módulo IceFlix"""
    def __init__(self, users_publisher, revocations_publisher):
        """Inicialización de la clase"""
        self.service_id = str(uuid.uuid4())
        self.users_publisher = users_publisher
        self.revocations_publisher = revocations_publisher
        self.lock = Lock()
        self.announcement_sub = None
        self.tokens = {}
        self.updated = False


    def refreshAuthorization(self, user, password_hash, current=None):
        """Lee el fichero de usuarios y comprueba credenciales correctas"""
        data = read_file_contents("users.json")

        if data.get(user) and data[user] == password_hash:
            new_token = token_urlsafe(40)
            self.tokens[new_token] = user

            logging.info(f"New token {new_token} granted to {user}. Publishing new token event")
            self.users_publisher.newToken(user, new_token, self.service_id)
            
            Timer(120.0, self.revocations_publisher.revokeToken, [new_token, self.service_id]).start()

            return new_token

        raise IceFlix.Unauthorized


    def isAuthorized(self, user_token, current=None):
        """Comprueba que el token de usuario esté en la lista de tokens"""
        return user_token in self.tokens


    def whois(self, user_token, current=None):
        """Devuelve el nombre de usuario a partir de un token"""
        if self.tokens.get(user_token):
            return self.tokens[user_token]

        raise IceFlix.Unauthorized


    def addUser(self, user, password_hash, admin_token, current=None):
        """Comprueba el token de administrador, lee todos los usuarios del fichero
        de usuarios y añade uno nuevo"""
        while True:
            try:
                main_service_id = choice(list(self.announcement_sub.mains.keys()))
                if not self.announcement_sub.mains[main_service_id].isAdmin(admin_token):
                    raise IceFlix.Unauthorized
                break
            except Ice.ConnectionRefusedException:
                logging.info(f"Main service {main_service_id} does not exist. Removing")
                self.announcement_sub.mains.pop(main_service_id)

        data = read_file_contents("users.json")

        if not data.get(user):
            data[user] = password_hash
            write_file("users.json", data)

        logging.info(f"User {user} added to database. Publishing add user event.")
        self.users_publisher.newUser(user, password_hash, self.service_id)


    def removeUser(self, user, admin_token, current=None):
        """Comprueba el token de administrador, lee todos los usuarios del fichero
        de usuarios y elimina uno de estos"""
        while True:
            try:
                main_service_id = choice(list(self.announcement_sub.mains.keys()))
                if not self.announcement_sub.mains[main_service_id].isAdmin(admin_token):
                    raise IceFlix.Unauthorized
                break
            except Ice.ConnectionRefusedException:
                logging.info(f"Main service {main_service_id} does not exist. Removing")
                self.announcement_sub.mains.pop(main_service_id)

        data = read_file_contents("users.json")
        if data.get(user):
            data.pop(user)
            write_file("users.json", data)
            logging.info(f"User {user} removed from database. Publishing revoke user event")
            self.revocations_publisher.revokeUser(user, self.service_id)


    def updateDB(self, database, service_id, current=None):
        """Actualiza la lista de usuarios a partir de la primera llamada recibida.
        Se ha usado cerrojos para tener exclusión mutua a la base de datos"""
        if service_id not in self.announcement_sub.authenticators:
            logging.info(f"Cannot update database. Service {service_id} unknown")
            raise IceFlix.UnknownService

        self.lock.acquire()
        if self.updated:
            self.lock.release()
            return

        logging.info("Updating database")
        self.updated = True
        users = database.userPasswords
        tokens = database.usersToken

        write_file("users.json", users)
        self.tokens = tokens
        self.lock.release()


    def share_data_with(self, service):
        """Share the current database with an incoming service."""
        users = read_file_contents("users.json")
        database = UsersDB_I(users, self.tokens)
        service.updateDB(database, self.service_id)



class AuthApp(Ice.Application):
    """Example Ice.Application for a Main service."""

    def __init__(self):
        super().__init__()
        self.servant = None
        self.proxy = None
        self.adapter = None
        self.announcer = None
        self.subscriber = None

    def get_topic(self, topic_manager, topic_name):
        try:
            return topic_manager.create(topic_name)
        except IceStorm.TopicExists:
            return topic_manager.retrieve(topic_name)

    def setup(self):
        """Configure the announcements sender and listener."""

        communicator = self.communicator()
        proxy = communicator.propertyToProxy("IceStorm.TopicManager")
        topic_manager = IceStorm.TopicManagerPrx.checkedCast(proxy)

        topic_announcement = self.get_topic(topic_manager, "ServiceAnnouncements")
        topic_users = self.get_topic(topic_manager, "Users")
        topic_revocations = self.get_topic(topic_manager, "Revocations")

        users_publisher = IceFlix.UserUpdatesPrx.uncheckedCast(topic_users.getPublisher())
        revocations_publisher = IceFlix.RevocationsPrx.uncheckedCast(topic_revocations.getPublisher())
    
        self.servant = AuthenticatorI(users_publisher, revocations_publisher)
    
        self.proxy = self.adapter.addWithUUID(self.servant)

        self.announcer = ServiceAnnouncementsSender(
            topic_announcement,
            self.servant.service_id,
            self.proxy,
        )

        self.subscriber = ServiceAnnouncementsListener(
            self.servant, self.servant.service_id, IceFlix.AuthenticatorPrx, self.proxy
        )


        subscriber_prx = self.adapter.addWithUUID(self.subscriber)
        users_prx = self.adapter.addWithUUID(UserUpdatesI(self.servant))
        revocations_prx = self.adapter.addWithUUID(RevocationsI(self.servant))

        topic_announcement.subscribeAndGetPublisher({}, subscriber_prx)
        topic_users.subscribeAndGetPublisher({}, users_prx)
        topic_revocations.subscribeAndGetPublisher({}, revocations_prx)


    def run(self, args):
        """Run the application, adding the needed objects to the adapter."""
        logging.info("Running Auth application")
        comm = self.communicator()
        self.adapter = comm.createObjectAdapter("Auth")
        self.adapter.activate()

        self.setup()
        self.announcer.start_service()

        self.shutdownOnInterrupt()
        comm.waitForShutdown()

        self.announcer.stop()
        return 0

AuthApp().main(sys.argv)