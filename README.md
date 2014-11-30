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

##Future Work
I'm a fan of Google App Engine. Perhaps next I'll write a request handler
to automatically perform this verification on all incoming requests.

##Acknowledgements
Thanks to Leah Culver for her [python-oauth library](https://github.com/leah/python-oauth/), 
used for Twitter oAuth verification.

##License:
This project is MIT licensed. See LICENSE.txt for more details. Enjoy!
