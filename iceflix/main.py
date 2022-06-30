#!/usr/bin/env python3
"""Module containing a template for a main service."""

import logging
import uuid
import sys
from threading import Lock
import Ice
import os
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

class Main(IceFlix.Main):
    """Servant for the IceFlix.Main interface.

    Disclaimer: this is demo code, it lacks of most of the needed methods
    for this interface. Use it with caution
    """

    def __init__(self, adminToken):
        """Create the Main servant instance."""
        self.service_id = str(uuid.uuid4()) 
        self.authenticators_proxies = []
        self.catalog_proxies = []
        self.adminToken = adminToken
        self.updated = False
        self.announcement_sub = None
        self.lock = Lock()

    def share_data_with(self, service):
        """Share the current database with an incoming service."""
        database = volatileServicesI(self.authenticators_proxies, self.catalog_proxies)
        service.updateDB(database, self.service_id)


    def updateDB(
        self, current_service, service_id, current
    ):  # pylint: disable=invalid-name,unused-argument
        """Receives the current main service database from a peer."""
        if service_id not in self.announcement_sub.mains:
            logging.info(f"Service {service_id} unknown")
            raise IceFlix.UnknownService

        self.lock.acquire()
        if self.updated:
            self.lock.release()
            return

        logging.info("Updating database")
        self.updated = True
        self.authenticators_proxies = current_service.authenticators
        self.catalog_proxies = current_service.mediaCatalogs
        self.lock.release()

        logging.info(
            "Receiving remote data base from %s to %s", service_id, self.service_id
        )

    def getAuthenticator(self, current=None):
        """Returns a registered authenticator proxy """
        service = None
        logging.info("Requested the authentication service")
        while True:
            try:
                if self.authenticators_proxies:
                    service = choice(self.authenticators_proxies)
                    service.ice_ping()
                    logging.info(f"Available authentication services: {self.authenticators_proxies}")
                    return service
                else:
                    logging.info("No authentication service is available")
                
                raise IceFlix.TemporaryUnavailable

            except (Ice.ObjectNotExistException, Ice.ConnectionRefusedException):
                self.authenticators_proxies.remove(service)

            except Ice.ConnectTimeoutException:
                raise IceFlix.TemporaryUnavailable

    def getCatalog(self, current=None):
        """Must return a registered catalog proxy"""
        service = None
        logging.info("Requested the catalog service")
        while True:
            try:
                if self.catalog_proxies:
                    service = choice(self.catalog_proxies)
                    service.ice_ping()
                    logging.info(f"Available catalog services: {self.catalog_proxies}")
                    return service

                logging.info("No catalog service is available")
                raise IceFlix.TemporaryUnavailable

            except (Ice.ObjectNotExistException, Ice.ConnectionRefusedException):
                self.announcement_sub.catalog_proxies.remove(service)

            except Ice.ConnectTimeoutException:
                raise IceFlix.TemporaryUnavailable
    
    def isAdmin(self, adminToken, current=None):
        return adminToken==self.adminToken


class volatileServicesI(IceFlix.VolatileServices):
    
    def __init__(self, authenticators, media_catalog):
        self.authenticators = authenticators
        self.mediaCatalogs = media_catalog


class MainApp(Ice.Application):
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
        proxy = communicator.propertyToProxy("IceStorm.TopicManager")
        topic_manager = IceStorm.TopicManagerPrx.checkedCast(proxy)

        try:
            topic = topic_manager.create("ServiceAnnouncements")
        except IceStorm.TopicExists:
            topic = topic_manager.retrieve("ServiceAnnouncements")

        self.announcer = ServiceAnnouncementsSender(
            topic,
            self.servant.service_id,
            self.proxy,
        )

        self.subscriber = ServiceAnnouncementsListener(
            self.servant, self.servant.service_id, IceFlix.MainPrx, self.proxy,
        )

        subscriber_prx = self.adapter.addWithUUID(self.subscriber)
        topic.subscribeAndGetPublisher({}, subscriber_prx)

    def run(self, args):
        """Run the application, adding the needed objects to the adapter."""
        logging.info("Running Main application")
        comm = self.communicator()
        self.adapter = comm.createObjectAdapter("Main")
        self.adapter.activate()

        admin_token = comm.getProperties().getProperty("AdminToken")
        self.servant = Main(admin_token)

        self.proxy = self.adapter.addWithUUID(self.servant)

        print(f"\n\nPROXY = {self.proxy}\n\nTOKEN DE ADMINISTRADOR = {admin_token}\n") 

        self.setup_announcements()

        self.announcer.start_service()

        self.shutdownOnInterrupt()
        comm.waitForShutdown()

        self.announcer.stop()
        return 0

MainApp().main(sys.argv)
