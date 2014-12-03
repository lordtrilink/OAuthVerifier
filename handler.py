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
the handler will respond with HTTP 401 unauthorized.

If you require a specific user to be logged in, call authorize_user(required_user="foo").
If the request does not use "foo"'s credentials, the handler will respond
with HTTP 401 Unauthorized.

"""


class OAuthHandler(webapp2.RequestHandler):

    #You can set a custom array of services you want to support.
    supported_services = [TWITTER_SERVICE, FACEBOOK_SERVICE, GOOGLE_SERVICE]

    #Only necessary for Twitter. These should be kept secret.
    consumer_key = None
    consumer_secret = None

    #Filled in by authorize_user() after successful execution.
    user_service = None
    user_id = None

    def authorize_user(self, required_user=None):
        try:
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

                self.user_id = verifier.TwitterVerifier(token,
                                                        user_id,
                                                        self.consumer_key,
                                                        self.consumer_secret,
                                                        token_secret).verify()
                self.user_service = TWITTER_SERVICE

            else:
                service = fb_goog_match.group(1)
                user_id = fb_goog_match.group(2)
                token = fb_goog_match.group(3)

                if service not in self.supported_services:
                    raise verifier.OAuthException("%s authentication not supported." % service)

                elif service == FACEBOOK_SERVICE:
                    self.user_id = verifier.FacebookVerifier(token, user_id)

                else:
                    self.user_id = verifier.GoogleVerifier(token, user_id)

                self.user_service = service

            if required_user and required_user != self.user_id:
                raise verifier.OAuthException("User %s is unauthorized." % user_id)

        except verifier.OAuthException as e:
            self.error(401)
            self.response.write(e.message)


