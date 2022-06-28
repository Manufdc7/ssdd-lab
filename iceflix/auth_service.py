#!/usr/bin/env python3
"""Module containing a template for a main service."""

import logging
import uuid
import sys
from threading import Lock
import Ice
import IceStorm
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



class AuthApp(Ice.Application):
    """Example Ice.Application for a Main service."""

    def __init__(self):
        super().__init__()
        self.servant = None
        self.proxy = None
        self.adapter = None
        self.announcer = None
        self.subscriber = None

    def setup_announcements(self):
        """Configure the announcements sender and listener."""

        communicator = self.communicator()
        proxy = communicator.stringToProxy("IceStorm/TopicManager:tcp -p 10000")
        #proxy = communicator.propertyToProxy("IceStorm.TopicManager")
        topic_manager = IceStorm.TopicManagerPrx.checkedCast(proxy)

        try:
            topic_announcement = topic_manager.create("ServiceAnnouncements")
            topic_users = topic_manager.create("UsersAnnouncements")
            topic_revocations = topic_manager.create("Revocations")

        except IceStorm.TopicExists:
            topic = topic_manager.retrieve("ServiceAnnouncements")

        self.announcer = ServiceAnnouncementsSender(
            topic,
            self.servant.service_id,
            self.proxy,
        )

        self.subscriber = ServiceAnnouncementsListener(
            self.servant, self.servant.service_id, IceFlix.MainPrx
        )

        subscriber_prx = self.adapter.addWithUUID(self.subscriber)
        topic.subscribeAndGetPublisher({}, subscriber_prx)

    def run(self, args):
        """Run the application, adding the needed objects to the adapter."""
        logging.info("Running Auth application")
        comm = self.communicator()
        self.adapter = comm.createObjectAdapter("Auth")
        self.adapter.activate()

        self.proxy = self.adapter.addWithUUID(self.servant)  # value de los diccionarios de todos los servicios

        self.setup_announcements()




        self.announcer.start_service()

        self.shutdownOnInterrupt()
        comm.waitForShutdown()

        self.announcer.stop()
        return 0

MainApp().main(sys.argv)
