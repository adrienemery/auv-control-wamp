import os
import requests

from twisted.internet.defer import inlineCallbacks
from twisted.logger import Logger

from autobahn.twisted.wamp import ApplicationSession, ApplicationRunner
from autobahn.wamp.exception import ApplicationError

AUTH_ID = 'authenticator'
TOKEN_VALIDATION_URL = os.getenv('TOKEN_VALIDATION_URL')

class AuthenticatorSession(ApplicationSession):

    log = Logger()

    @inlineCallbacks
    def onJoin(self, details):

        def authenticate(realm, authid, details):
            ticket = details['ticket']
            headers = {'Authorization': 'Token {}'.format(ticket)}
            response = requests.post(TOKEN_VALIDATION_URL, headers=headers)
            logger.debug(response)
            if response.status_code == 200:
                # TODO store roles in database for different components
                # return default role
                return 'default'
            else:
                raise ApplicationError("com.auv.invalid_ticket",
                                       "could not authenticate session - invalid ticket "
                                       f"'{ticket}' for principal {authid}")

        # register authenticate method
        try:
            yield self.register(authenticate, 'com.auv.authenticate')
            self.log.info("WAMP-Ticket dynamic authenticator registered!")
        except Exception as exc:
            self.log.warning(f"Failed to register dynamic authenticator: {exc}")
