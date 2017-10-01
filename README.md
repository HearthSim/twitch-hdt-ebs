# Twitch HDT EBS

Twitch Extension Backend Service for [Hearthstone Deck Tracker](https://hsdecktracker.net).


## API Usage

### Authentication

Authentication happens exclusively through HSReplay.net OAuth2.
The API accepts valid [OAuth2 Bearer Tokens](https://github.com/HearthSim/HSReplay.net/wiki/OAuth2-API-docs).

### Twitch Metadata Headers

With every request, the following two headers should be send:

* **X-Twitch-Client-Id**: The client ID of the configured extension.
  An HTTP 400 will be returned if this header is missing or not valid.
* **X-Twitch-User-Id**: The Twitch User ID (channel ID) of the user's Twitch channel.
  An HTTP 400 will be returned if this header is missing.
* **X-Twitch-Extension-Version**: The version of the extension that has been installed.
  Only used if available (eg. by Javascript clients).

The Twitch User ID must correspond to a [linked Twitch account on HSReplay.net](https://hsreplay.net/account/social/connections/)
for the same account as the one the client authenticates itself against.
If the User ID is not one of the account's linked Twitch accounts, an HTTP 403
will be returned with the error `channel_not_allowed` and extra details.
Example:

```
POST /send/ HTTP/1.1
Accept: application/json
Authorization: Bearer xxxxxxxxxxxx
X-Twitch-Client-Id: d72hk844mgvex3kbfhrgjtdoeqrh0t
X-Twitch-User-Id: 1111111
...

HTTP/1.0 403 Forbidden
Allow: POST, OPTIONS
Content-Type: application/json

{
    "available_channels": ["123456", "123654"],
    "error": "channel_not_allowed",
    "detail": "No permission for channel '1111111'"
}
```


### `POST /send/`: PubSub Send endpoint

The `/send/` endpoint allows sending pubsub JSON messages to the twitch channel specified in the `X-Twitch-User-Id` HTTP header.
The endpoint expects a POST with data formatted as `{"type": "...", "data": {...}}`.
The input is validated, signed with the extension's locally-configured secret, then
[submitted to the Twitch Extension PubSub API](https://dev.twitch.tv/docs/extensions/reference#send-extension-pubsub-message).


### `POST /setup/`: Verify and update setup state

The `/setup/` endpoint takes the same twitch metadata headers but expects no input.
Authentication happens using a Twitch JWT which is verified then paired up with a HearthSim user.
This endpoint allows verifying that OAuth2 permissions and Twitch setup is in order. Upon HTTP POST,
the Twitch user's extension's `required_configuration` setting
[will be updated](https://dev.twitch.tv/docs/extensions/reference#set-extension-required-configuration)
to signal the setup being complete, thereby allowing the user to complete the extension setup on Twitch.


## EBS configuration

### Settings

The EBS looks for the following application settings:

* `EBS_APPLICATIONS`: A dictionary of Twitch Extension Client ID -> Configuration for each configured extension.
  The expected configuration is a `secret` string, which is the extension secret (as provided in Base64), and an
  `owner_id` string, which is the owner ID of the Twitch extension.
* `EBS_JWT_TTL_SECONDS`: The TTL (in seconds) of JWTs used to communicate with the Twitch API. Default: `120`
