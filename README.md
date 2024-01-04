# Express-Hawk (Middleware)

This module provides a [Hawk](https://github.com/hueniverse/hawk)
authentication middleware for [Express](https://github.com/expressjs/express) v4.x applications. 

Has support for both the standard request with `Authorization` header and a pre-authorized `bewit` in the query string.

## Installation

To use the package, you'll need to add the dependency:

    npm install --save dreyer/express-hawk
    
To run the tests if you're doing development on the library:

	npm test

## Usage

In order to use Hawk within your application, you'll need to use it as
a middleware:

```javascript
var express = require('express');
var hawk = require('express-hawk');

var app = express();

var port = 8081;
var host = 'localhost';

function getCredentials(id) {
    return {
        id: '1',
        key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
        algorithm: 'sha256',
        user: 'steve'
    };
}

var authentication = hawk.getMiddleware({
    getSession: function (id, cb) {
        console.log('middleware.getSession: id=' + id);

        // A function which pass to the cb the key and algorithm for the
        // given token id. First argument of the callback is a potential
        // error.

        var credentials = getCredentials(id);

        cb(null, credentials);
    },
    setSession: function (req, res, credentials, cb) {
        console.log('middleware.setSession: credentials=', credentials);

        // A function which stores a session for the given id and key.
        // Argument returned is a potential error.
        req.credentials = credentials;

        cb(null);
    }
});

app.use(function (req, res, next) {
    console.log('app.use: ' + req.method + ' ' + req.url);
    next();
});

app.get('/', function (req, res) {
    res.send('Hello World');
});

app.get('/secured', authentication);

app.listen(port, function () {
    console.log('app.listen: http://' + host + ':' + port + "\n");
});
```

The middleware only takes one argument, which is a `config` object containing
parameters defined below:

| Name | Type | Description |
| ---- | ---- | ----------- |
| `options` | Object | Additional options to pass to the underlying Hawk functions for `hawk.uri.authenticate` and `hawk.server.authenticate`. This is particularly helpful for overriding the `options.host` and `options.port`. |
| `getSession` | Function | Define how to find the credentials from the identifier of the session and a callback argument: `getSession(id, callback)`. The `callback` is executed when the search operation has finished. The signature for the callback is `callback(err, credentials)`. In the event that the record doesn't exist, you can call `callback(null, null)`. |
| `setSession` | Function | Define how to store a new session credentials for the duration of the request. `setSession(req, res, credentials, callback)`. The `callback` is executed when storage has finished using the signature `callback(err, credentials, callback)`. |
| `sendError` | Function | Parse errors generated by the library. In the format: `sendError(res, statusCode, reasonPhrase, payload)` |


### Bewit

You can add support for limited and short-term access to a protected resource for a third party which does not have access to the shared credentials using Hawk's [*bewit*](https://github.com/hueniverse/hawk#single-uri-authorization).
 

```javascript
var hawk = require('express-hawk');

function getCredentials(id) {
    return {
        id: '1',
        key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
        algorithm: 'sha256',
        user: 'steve'
    };
}

var ttlSec = 300; // 5 mins
var url = 'http://www.example.org/foobar';
var bewit = hawk.getToken(getCredentials(), url, ttlSec);

url += '?bewit=' + bewit;

console.log(url);

// http://www.example.org/foobar?bewit=MVwxNDg2MTM2NTUyXFBOTFpEMXpPd2NFOEZHUmpEVmZFZDRzemsrTDVzNUZTUDRtVFRPclBSajg9XA
```        
    
## Contributing

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D

## History

See [CHANGELOG.md](./CHANGELOG.md)

## Credits

Thanks to the Mozilla team for the idea: [mozilla-services/express-hawkauth](https://github.com/mozilla-services/express-hawkauth)

## License

MIT