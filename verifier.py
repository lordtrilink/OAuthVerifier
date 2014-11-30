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


class TwitterVerifier(OAuthVerifier):
    consumer_key = None
    consumer_secret = None
    token_secret = None

    def __init__(self, token, user_id, consumer_key, consumer_secret, token_secret):
        OAuthVerifier.__init__(self, token, user_id,
                               "https://api.twitter.com/1.1/account/verify_credentials.json",
                               "id_str")
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

        try:
            req = urllib2.Request(self.url, headers=headers)
            result = urllib2.urlopen(req)
            response = result.read()

            print response

            result_dict = json.loads(response)

            if self.user_id_field in result_dict and result_dict[self.user_id_field] == self.user_id:
                return

            raise OAuthException()

        except urllib2.HTTPError as e:
            if e.code == 401:
                raise OAuthException()
            else:
                raise e

