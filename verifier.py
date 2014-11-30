__author__ = 'Nigel Brady'

import urllib
import urllib2
import json


class OAuthVerifier:
    token = None
    user_id = None
    url = None
    user_id_field = None

    def __init__(self, token, user_id, url, user_id_field="id"):
        self.token = token
        self.user_id = user_id
        self.url = url
        self.user_id_field = user_id_field

    def verify(self):
        if not self.token or not self.user_id:
            raise Exception("You must provide a user ID and oAuth access token to proceed.")

        params = {"access_token": self.token}
        query_string = urllib.urlencode(params)
        request = self.url + "?" + query_string

        try:
            result = urllib2.urlopen(request)
            response = result.read()

            result_dict = json.loads(response)

            if self.user_id_field in result_dict and result_dict[self.user_id_field] == self.user_id:
                return

            raise OAuthException()

        except urllib2.HTTPError as e:
            if e.code == 401:
                raise OAuthException()
            else:
                raise e


class OAuthException(Exception):
    def __init__(self):
        Exception.__init__(self, "Access token invalid or does not belong to the current user.")


class FacebookVerifier(OAuthVerifier):

    def __init__(self, token, user_id):
        OAuthVerifier.__init__(self, token, user_id, "https://graph.facebook.com/me")


class GoogleVerifier(OAuthVerifier):

    def __init__(self, token, user_id):
        OAuthVerifier.__init__(self, token, user_id, "https://www.googleapis.com/oauth2/v1/tokeninfo", "user_id")


