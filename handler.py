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

__author__ = 'nigel'

import webapp2
import verifier
import re
import hashlib

from google.appengine.api import memcache

TWITTER_SERVICE = "Twitter"
FACEBOOK_SERVICE = "Facebook"
GOOGLE_SERVICE = "Google"

"""
A simple webapp2 request handler that can check oAuth Authorizations
for popular social services.

By default, Twitter, Facebook and Google services are supported.
To choose which services you support, override the supported_services
array in your subclass. For example, to support only Facebook authentication:

supported_services = [FACEBOOK_SERVICE]

If you support Twitter Authentication, be sure to se the consumer_key
and consumer_secret properties:

self.consumer_key = "abc"
self.consumer_secret = "def"

Authorization headers on requests should take the following form:

Facebook -> Authorization: Facebook <user_id>|<auth_token>
Google -> Authorization: Google <user_id>|<auth_token>
Twitter/Digits -> Authorization: Twitter <user_id>|<auth_token>|<auth_token_secret>

To check user authorization, call authorize_user(). If the oAuth token is valid,
and belongs to the specified user_id, the following instance properties will be available:

self.user_id #The User's ID from the social service.
self.user_service #The service used to log in ('Facebook', 'Google', or 'Twitter')

If the oAuth token is invalid, or does not belong to the specified user,
the handler will throw an OAuthException.

If you require a specific user to be logged in, call authorize_user(required_user="foo").
If the request does not use "foo"'s credentials, the handler will raise an OAuthException.

If you don't want to deal with exceptions, use try_authorize_user(), which returns True
if the authorization succeeded and False if it failed.

"""


class OAuthHandler(webapp2.RequestHandler):
  # You can set a custom array of services you want to support.
  supported_services = [TWITTER_SERVICE, FACEBOOK_SERVICE, GOOGLE_SERVICE]

  #Only necessary for Twitter. These should be kept secret.
  consumer_key = None
  consumer_secret = None

  #Filled in by authorize_user() after successful execution.
  user_service = None
  user_id = None

  #Cut down on network traffic by saving oAuth tokens
  #to memcache. Requests can then be verfied without hitting the
  #service provider. Note that if you turn this option off,
  # you might run up against rate limits from the 3rd party provider.
  use_credential_caching = True

  #Expiration time for cached tokens
  credential_caching_period = 900

  def authorize_user(self, required_user=None):

    authorization_header = self.request.headers.get("Authorization")

    if not authorization_header:
      raise verifier.OAuthException("Authorization header is required.")

    fb_goog_re = re.compile("(Facebook|Google) (.+)\|(.+)")
    twitter_re = re.compile("Twitter (.+)\|(.+)\|(.+)")

    fb_goog_match = fb_goog_re.match(authorization_header)
    twitter_match = twitter_re.match(authorization_header)

    if not fb_goog_match and not twitter_match:
      raise verifier.OAuthException("Malformed authorization header.")

    if twitter_match:

      if TWITTER_SERVICE not in self.supported_services:
        raise verifier.OAuthException("Twitter authentication not supported.")

      user_id = twitter_match.group(1)
      token = twitter_match.group(2)
      token_secret = twitter_match.group(3)

      if not self.load_cached_credentials(TWITTER_SERVICE, user_id, token, token_secret):
        self.user_id = verifier.TwitterVerifier(token,
                                                user_id,
                                                self.consumer_key,
                                                self.consumer_secret,
                                                token_secret).verify()
        self.user_service = TWITTER_SERVICE

        self.cache_credentials(TWITTER_SERVICE, user_id, token, token_secret)

    else:
      service = fb_goog_match.group(1)
      user_id = fb_goog_match.group(2)
      token = fb_goog_match.group(3)

      if service not in self.supported_services:
        raise verifier.OAuthException("%s authentication not supported." % service)

      elif self.load_cached_credentials(service, user_id, token):
        pass

      elif service == FACEBOOK_SERVICE:
        self.user_id = verifier.FacebookVerifier(token, user_id).verify()
        self.user_service = FACEBOOK_SERVICE

        self.cache_credentials(FACEBOOK_SERVICE, user_id, token)

      else:
        self.user_id = verifier.GoogleVerifier(token, user_id).verify()
        self.user_service = GOOGLE_SERVICE

        self.cache_credentials(GOOGLE_SERVICE, user_id, token)

    if required_user and required_user != self.user_id:
      raise verifier.OAuthException("User %s is unauthorized." % user_id)

  def try_authorize_user(self, required_user=None):
    try:
      self.authorize_user(required_user)
      return True
    except verifier.OAuthException as e:
      return False

  @staticmethod
  def key_for_credentials(service, user_id, token, token_secret=None):

    key = "OAuthVerifier|{0}|{1}|{2}".format(service, user_id, token)

    if token_secret:
      key += "|{0}".format(token_secret)

    return hashlib.sha256(key).hexdigest()

  def load_cached_credentials(self, service, user_id, token, token_secret=None):

    cache_key = OAuthHandler.key_for_credentials(service, user_id, token, token_secret)

    if self.use_credential_caching and memcache.get(cache_key):
      self.user_id = user_id
      self.user_service = service
      print("Found cached credentials.")
      return True

    else:
      print("Caching is off or credentials not found.")
      return False

  def cache_credentials(self, service, user_id, token, token_secret=None):
    cache_key = OAuthHandler.key_for_credentials(service, user_id, token, token_secret)
    memcache.add(cache_key, True, time=self.credential_caching_period)








