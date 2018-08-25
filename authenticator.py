import os
import logging
import requests

from twisted.internet.defer import inlineCallbacks

from autobahn.twisted.wamp import ApplicationSession, ApplicationRunner
from autobahn.wamp.exception import ApplicationError

logger = logging.getLogger(__name__)
AUTH_ID = 'authenticator'
TOKEN_VALIDATION_URL = os.getenv.('TOKEN_VALIDATION_URL')

class AuthenticatorSession(ApplicationSession):

    def onConnect(self):
        print('Connecting to {} as {}'.format(self.config.realm, AUTH_ID))
        self.join(realm=self.config.realm, authmethods=['ticket'], authid=AUTH_ID)

    @inlineCallbacks
    def onJoin(self, details):

        def authenticate(realm, authid, details):
            ticket = details['ticket']
            headers = {'Authorization': 'Token {}'.format(ticket)}
            response = requests.post(TOKEN_VALIDATION_URL,
                                     headers=headers)
            logger.debug(response)
            if response.status_code == 200:
                # TODO store roles in database for different components
                # return default role
                return 'default'
            else:
                raise ApplicationError("com.auv.invalid_ticket",
                                       "could not authenticate session - invalid ticket "
                                       "'{}' for principal {}".format(ticket, authid))

        # register authenticate method
        try:
            yield self.register(authenticate, 'com.auv.authenticate')
            logger.info("WAMP-Ticket dynamic authenticator registered!")
        except Exception as e:
            logger.warning("Failed to register dynamic authenticator: {0}".format(e))
