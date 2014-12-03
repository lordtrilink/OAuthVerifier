"""The MIT License

Copyright (c) 2007 Nigel Brady

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE. """

"""
This is script is a tool that can be used by servers to verify oAuth tokens.

To speed login flow, many mobile apps allow users to log in with their
Facebook/Google/Twitter accounts. The results of such logins are stable
User IDs that can be added to the database of your backend server.

However, how can your server know if the request is really coming from
a given User ID? You need to check the oAuth token coming from the mobile
application, and that's what this script does.

Facebook/Google:

facebook_token = "abc"
facebook_id = "123"
facebook_verifier = FacebookVerifier(facebook_token, facebook_id)

google_token = "def"
google_id = "456"
google_verifier = GoogleVerifier(google_token, google_id)


try:
    facebook_verifier.verify()
    google_verifier.verify()

except OAuthException as e:
    #An exception is thrown if the oAuth token is invalid or doesn't belong to
    #the provided user ID.

---

Twitter:

Twitter uses the oAuth 1.0 API which makes things more complicated. You'll need:

Your application's consumer key (keep it secret!)
Your application's consumer secret (keep it secret!)
Your user's oAuth token (get this from the mobile Twitter SDK)
your user's oAuth token secret (get this from the mobile Twitter SDK)

tw_token = "abc"
tw_token_secret = "def"
tw_id = "789"
tw_consumer_key = "foo"
tw_consumer_secret = "bar"

tw_verifier = verifier.TwitterVerifier(tw_token,
                                       tw_id,
                                       tw_consumer_key,
                                       tw_consumer_secret,
                                       tw_token_secret)

try:
    tw_verifier.verify()

except OAuthException as e:
    #An exception is thrown if the oAuth token is invalid or doesn't belong to
    #the provided user ID.

"""

__author__ = 'Nigel Brady'

import urllib
import urllib2
import json
import oauth


class OAuthVerifier:
    token = None
    user_id = None
    url = None
    user_id_field = None
    request = None
    debug = False

    def __init__(self, token, user_id, url, user_id_field="id", debug=False):
        self.token = token
        self.user_id = user_id
        self.url = url
        self.user_id_field = user_id_field
        self.debug = debug

    def verify(self):
        if not self.token or not self.user_id:
            raise Exception("You must provide a user ID and oAuth access token to proceed.")

        params = {"access_token": self.token}
        query_string = urllib.urlencode(params)
        self.request = self.url + "?" + query_string
        return self.execute_request()

    def execute_request(self):
        try:
            result = urllib2.urlopen(self.request)
            response = result.read()

            result_dict = json.loads(response)

            if self.debug:
                print response

            if self.user_id_field in result_dict and result_dict[self.user_id_field] == self.user_id:
                return result_dict[self.user_id_field]
            else:
                raise OAuthException()

        except urllib2.HTTPError as e:
            if e.code == 401:
                raise OAuthException()
            else:
                raise e


class OAuthException(Exception):
    def __init__(self):
        Exception.__init__(self, "Access token invalid or does not belong to the current user.")

    def __init__(self, message):
        Exception.__init__(self, message)


class FacebookVerifier(OAuthVerifier):
    def __init__(self, token, user_id, debug=False):
        OAuthVerifier.__init__(self,
                               token,
                               user_id,
                               "https://graph.facebook.com/me",
                               debug=debug)


class GoogleVerifier(OAuthVerifier):
    def __init__(self, token, user_id, debug=False):
        OAuthVerifier.__init__(self,
                               token,
                               user_id,
                               "https://www.googleapis.com/oauth2/v1/tokeninfo",
                               "user_id", debug=debug)


class TwitterVerifier(OAuthVerifier):
    consumer_key = None
    consumer_secret = None
    token_secret = None

    def __init__(self, token, user_id, consumer_key, consumer_secret, token_secret, debug=False):
        OAuthVerifier.__init__(self,
                               token,
                               user_id,
                               "https://api.twitter.com/1.1/account/verify_credentials.json",
                               "id_str",
                               debug=debug)

        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.token_secret = token_secret

    def verify(self):
        consumer = oauth.OAuthConsumer(self.consumer_key, self.consumer_secret)
        signature_method_hmac_sha1 = oauth.OAuthSignatureMethod_HMAC_SHA1()
        oauth_token = oauth.OAuthToken(self.token, self.token_secret)

        oauth_request = oauth.OAuthRequest.from_consumer_and_token(consumer,
                                                                   token=oauth_token,
                                                                   http_method='GET',
                                                                   http_url=self.url)

        oauth_request.sign_request(signature_method_hmac_sha1, consumer, oauth_token)

        headers = oauth_request.to_header()
        self.request = urllib2.Request(self.url, headers=headers)
        return self.execute_request()




