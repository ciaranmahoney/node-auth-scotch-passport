// config/auth.js

// Add api keys and rename to auth.js

// expose config directly to app
module.exports = {

    'facebookAuth'  : {
        'clientID'          : 'ID HERE',
        'clientSecret'      : 'SECRET HERE', 
        'callbackURL'       : 'http://localhost:8080/auth/facebook/callback'
    },

    'twitterAuth'   : {
        'consumerKey'       : 'KEY HERE',
        'consumerSecret'    : 'SECRET HERE',
        'callbackURL'       : 'http://localhost:8080/auth/twitter/callback'
    },

    'googleAuth' : {
        'clientID'      : 'ID HERE',
        'clientSecret'  : 'SECRET HERE',
        'callbackURL'   : 'http://localhost:8080/auth/google/callback'
    }
};