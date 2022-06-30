#!/usr/bin/env python3
"""Module containing a template for a main service."""

#pylint: disable=no-member, invalid-name, unused-argument, import-error, wrong-import-position, logging-format-interpolation, logging-fstring-interpolation

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

logging.getlogging().setLevel(logging.DEBUG)


def read_file_contents(file_name):
    """Reads from a file"""
    data = {}
    with open(file_name, "r", encoding="utf-8") as file:
        if os.stat("users.json").st_size != 0:
            data = json.load(file)
    return data

def write_file(file_name, contents):
    """It writes in a file"""
    with open(file_name, "w", encoding="utf-8") as file:
        json.dump(contents, file)


class UsersDB_I(IceFlix.UsersDB):
    """Structure formed by users and the hash of their respectives passwords"""
    def __init__(self, user_passwords, users_token):
        self.userPasswords = user_passwords
        self.usersToken = users_token


class UserUpdatesI(IceFlix.UserUpdates):
    """Implementation of the events channel of updates from users and tokens."""
    def __init__(self, auth_service):
        self.auth_service = auth_service

    def newUser(self, user, pass_hash, srv_id, current=None):
        """New user token"""
        logging.info("New user event received")
        if srv_id != self.auth_service.uuid and srv_id in self.auth_service.announcement_sub.authenticators:
            logging.info(f"New user {user} added to database")
            data = read_file_contents("users.json")

            if not data.get(user):
                data[user] = pass_hash
                write_file("users.json", data)

    def newToken(self, user, token, srv_id, current=None):
        """New Token event"""
        logging.info("New token event received")
        if srv_id != self.auth_service.service_id and srv_id in self.auth_service.announcement_sub.authenticators:
            logging.info(f"New token {token} for user {user} added to database")
            self.auth_service.tokens[token] = user


class RevocationsI(IceFlix.Revocations):
    """Implementation of the events channel of revocations from users and tokens."""
    def __init__(self, auth_service):
        self.auth_service = auth_service

    def revokeToken(self, token, srv_id, current=None):
        """Removes a token"""
        logging.info("Revoked token event received")
        if srv_id != self.auth_service.service_id and srv_id in self.auth_service.announcement_sub.authenticators and token in self.auth_service.tokens:
            logging.info(f"Token {token} has been deleted")
            self.auth_service.tokens.pop(token)

    def revokeUser(self, user, srv_id, current=None):
        """It removes a user"""
        logging.info("Revoked user event received")
        if srv_id != self.auth_service.service_id and srv_id in self.auth_service.announcement_sub.authenticators:
            logging.info(f"User {user} has been deleted")
            data = read_file_contents("users.json")

            if data.get(user):
                data.pop(user)
                write_file("users.json", data)


class AuthenticatorI(IceFlix.Authenticator):
    """Implementation of the Authenticator interface from the IceFlix Module"""
    def __init__(self, users_publisher, revocations_publisher):
        """Class initialization"""
        self.service_id = str(uuid.uuid4())
        self.users_publisher = users_publisher
        self.revocations_publisher = revocations_publisher
        self.lock = Lock()
        self.anonuncement_sub = None
        self.tokens = {}
        self.updated = False


    def refreshAuthorization(self, user, password_hash, current=None):
        """Reads the file of the users and checks if the credentials are correct"""
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
        """Check the token of the user is inside the list of the tokens"""
        return user_token in self.tokens


    def whois(self, user_token, current=None):
        """Returns the name of the user from a token"""
        if self.tokens.get(user_token):
            return self.tokens[user_token]

        raise IceFlix.Unauthorized


    def addUser(self, user, password_hash, admin_token, current=None):
        """It checks the admin token, read all the users from the file of users and add a new one"""
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
        """It checks the admin token, reads all the users from the file and remove one of them"""
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
            self.revocations_publisher.revokeUser(user, self.uuid)


    def updateDB(self, database, service_id, current=None):
        """Updates the users list from the first call received. Locks have been used to have mutual exclusion
        to the DB""" 
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