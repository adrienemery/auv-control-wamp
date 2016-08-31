import envitro
import requests

from twisted.internet.defer import inlineCallbacks

from autobahn.twisted.wamp import ApplicationSession, ApplicationRunner
from autobahn.wamp.exception import ApplicationError


AUTH_ID = 'authenticator'
AUTH_TICKET = envitro.str('AUTH_TICKET', '@1ox6*xba-t23l)y_&#_2#7epg-3oc&e@^kmgw7nk*e#g)5f_^')


class AuthenticatorSession(ApplicationSession):

    def onConnect(self):
        print('Connecting to {} as {}'.format(self.config.realm, AUTH_ID))
        self.join(realm=self.config.realm, authmethods=['ticket'], authid=AUTH_ID)

    def onChallenge(self, challenge):
        if challenge.method == 'ticket':
            print("WAMP-Ticket challenge received: {}".format(challenge))
            return AUTH_TICKET
        else:
            raise Exception("Invalid authmethod {}".format(challenge.method))

    @inlineCallbacks
    def onJoin(self, details):

        def authenticate(realm, authid, details):
            ticket = details['ticket']
            headers = {'Authorization': 'Token {}'.format(ticket)}
            response = requests.post('http://0.0.0.0:8000/api/auth/validate-token/',
                                     headers=headers)
            print(response)
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
            print("WAMP-Ticket dynamic authenticator registered!")
        except Exception as e:
            print("Failed to register dynamic authenticator: {0}".format(e))
