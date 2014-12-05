# oAuthVerifier
## Quickly verify your Facebook/Twitter/Google oAuth users.

This is script is a tool that can be used by servers to verify oAuth tokens.

To speed login flow, many mobile apps allow users to log in with their
Facebook/Google/Twitter accounts. The results of such logins are stable
User IDs that can be added to the database of your backend server.

However, how can your server know if the request is really coming from
a given User ID? You need to check the oAuth token coming from the mobile
application, and that's what this script does.

##Facebook/Google:

You'll need:

    - Your user's oAuth token
    - Your user's ID
    
You'll usually get these values from a successful login with the Facebook/Google mobile SDKs.

```python

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

```

##Twitter:

Twitter uses the oAuth 1.0 API which makes things more complicated. You'll need:

    -Your application's consumer key (keep it secret!)
    -Your application's consumer secret (keep it secret!)
    
You are assigned these values when you create your application on Twitter's developer page.

You'll also need:
    
    -Your user's ID
    -Your user's oAuth token
    -Your user's oAuth token secret
    
You get these values from a successful login with the Twitter mobile SDK.
    
```python

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
    
```

##Google App Engine (webapp2) Handler:

I originally wrote this tool for use with Google App Engine. The idea is to collect the oAuth information in the HTTP headers and use the verifier classes to check it. This class handles most of the heavy lifting for you!

On the mobile end, put the following in your HTTP Authorization header:

**Facebook**
```
Authorization: Facebook <user_id>|<auth_token>
```
**Google**
```
Authorization: Google <user_id>|<auth_token>
```
**Twitter**
```
Authorization: Twitter <user_id>|<auth_token>|<auth_token_secret>
```

On the server end, inherit from the OAuthHandler class and respond to the request as follows:

```python

from OAuthVerifier import handler
from OAuthVerifier.verifier import OAuthException

class HelloHandler(handler.OAuthHandler):

  #Set these properties if you're using Twitter authentication.
  consumer_key = "abc"
  consumer_secret = "def"
  
  def get(self):
    try:
      self.authorize_user() #Throws an OAuthException if it fails.
      
      #Authorization succeeded! Use self.user_id and self.user_service
      #to get the user ID and service used to log in (Twitter, Facebook, Google)
      
      self.response.write('Hello world!\n')
      self.response.write('You logged in with %s\n' % self.user_service)
      self.response.write('Your User ID is: %s' % self.user_id)

    except OAuthException as e:
      self.error(401)
      self.response.write("Authorization failed: %s" % e.message)
      print traceback.format_exc()

    except Exception as e:
      self.error(401)
      self.response.write("Something went wrong: %s" % e.message)
      print traceback.format_exc()
      
```

To avoid hitting the social services with every request, oAuth tokens are SHA256 hashed
and stored in memcache for 15 minutes. You can turn this behavior off, or adjust the caching
period as follows:

```python
class NoCacheHandler(handler.OAuthHandler):

    use_credential_caching = False #Turn off caching...
    credential_caching_period = 900 # Or change caching period...
```

Note that if you turn caching off entirely, you might run into API rate limits from Twitter
and other services.

##Acknowledgements
Thanks to Leah Culver for her [python-oauth library](https://github.com/leah/python-oauth/), 
used for Twitter oAuth verification.

##License:
This project is MIT licensed. See LICENSE.txt for more details. Enjoy!
