// config/passport.js

// load dependencies 
var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var TwitterStrategy = require('passport-twitter').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy

// load user model
var User = require('../app/models/user');

// load the auth variables
var configAuth = require('./auth');

// expose passport function to our app using module.exports
module.exports = function(passport) {

    // =============================
    // Passport session setup
    // =============================

    // required for persistent login sessions
    // passport needs ability to serialize and unserialize users out of session

    // serialize user for the session
    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    // deserialize users for session
    passport.deserializeUser(function(id, done){
        User.findById(id, function(err, user){
            done(err, user);
        });
    });

    // =============================
    // Local Signup
    // =============================

    // We are using named strategies since we have one for login and one for signup
    // by default, if there was no name, it would just be called local

    passport.use('local-signup', new LocalStrategy({
        // be default, local strategy uses username and password - we will overide with email.

        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass back the entire request to the callback
    },
    function(req, email, password, done) {
        // asynchronous
        // User.findOne won't fire unless data is sent back
        process.nextTick(function() {
            // find a user whose email is the same as the forms email
            // we are checking to see if the user trying to login already exists

            User.findOne({ 'local.email' : email }, function(err, user){
                // if there are errors, return the error
                if (err)
                    return done (err);

                // check to see if there's already a user with that email
                if (user) {
                    return done(null, false, req.flash('signupMessage', 'Sorry, a user with that email already exists.'
                ));
                } else {
                    // if there is no user with that email, create user
                    var newUser = new User();

                    // set users's local credentials
                    newUser.local.email = email;
                    newUser.local.password = newUser.generateHash(password);

                    // save user
                    newUser.save(function(err){
                        if(err)
                            throw err;
                        return done(null, newUser, req.flash('signupMessage', 'Thanks for loggin in!'));
                    });
                }
            });
        });
    })); // end local signup

    // =============================
    // Local Login
    // =============================
    // We are using named strategies since we have one for login and one for signup
    // by default, if there was no name, it would just be called local

    passport.use('local-login', new LocalStrategy({
        // be default, local strategy uses username and password - we will overide with email.

        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass back the entire request to the callback
    },
    function(req, email, password, done) {
        // asynchronous
        // User.findOne won't fire unless data is sent back
        process.nextTick(function() {

            // find a user whose email is the same as the form's email
            // we are checking to see if the user trying to login already exists
            User.findOne({ 'local.email' : email }, function(err, user) {
                // If errors, return the error first
                if (err) 
                    return done(err);

                // if no user is found or password is wrong, return an error message
                if (!user || !user.validPassword(password))
                    return done(null, false, req.flash('loginMessage', 'Invalid username or password')); // req.flash sets flash data useing connect-flash
                
                // all is well, return successful user
                return done(null, user);
            });
        });
    }));
    
    // =============================
    // Facebook Login
    // =============================
    passport.use(new FacebookStrategy({

        // pull in app id and secret from auth.js
        clientID        : configAuth.facebookAuth.clientID,
        clientSecret    : configAuth.facebookAuth.clientSecret,
        callbackURL     : configAuth.facebookAuth.callbackURL,
        passReqToCallback : true // allows us to pass in the request from our route to check if user is logged in
    },

    // facebook will send back token and profile
    function(req, token, refreshToken, profile, done) {
        // async
        process.nextTick(function() {

            // Check is user is logged in
            if(!req.user){ 

                // find user in database based on FB id
                User.findOne({ 'facebook.id' : profile.id }, function (err, user) {
                    // if there is an error, stop and return that
                    if (err)
                        return done(err);

                    // if user found, log them in
                    if (user) {
                        return done(null, user);

                    } else {
                        // If user not found, create them
                        var newUser = new User();
                        newUser.facebook.id = profile.id; // set user id

                        newUser.facebook.token = token; // save token that fb provies

                        newUser.facebook.name = profile.name.givenName + ' ' + profile.name.familyName; 

                        newUser.facebook.email = profile.emails[0].value; // get first email from facebook profile

                        newUser.save(function(err) {
                            if(err)
                                throw err;
                            return done(null, newUser);
                        });
                }
                });
            } else {
                // User already exists and is logged in, we have to link accounts
                var user = req.user; // pull user out of session

                // update the current user's facebook credentials
                user.facebook.id = profile.id;
                user.facebook.token = token;
                user.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
                user.facebook.email = profile.emails[0].value;

                // save user
                user.save(function(err) {
                    if(err)
                        throw err;
                    return done(null, user);
                });
            }
        });
    }));

    // =============================
    // Twitter Login
    // =============================

    passport.use(new TwitterStrategy({
        consumerKey     : configAuth.twitterAuth.consumerKey,
        consumerSecret  : configAuth.twitterAuth.consumerSecret,
        callbackURL     : configAuth.twitterAuth.callbackURL
    },
    function(req, token, tokenSecret, profile, done) {
        // make code asyncronous
        // User.findone won't fire until we have data back from Twitter
        process.nextTick(function() {

            // Check if user is logged in
            if (!req.user) {   
                // User not logged in so create account 
                User.findOne( { 'twitter.id' : profile.id }, function(err, user){
                    // if error, stop and return that
                    if(err)
                        return done(err)

                    // if user found, log them in
                    if(user) {
                        return done(null, user);
                    } else {
                        // if user not found, create them
                        var newUser = new User();
                        newUser.twitter.id          = profile.id;
                        newUser.twitter.token       = token;
                        newUser.twitter.username    = profile.username; 
                        newUser.twitter.displayName = profile.displayName;

                        // save user into database
                        newUser.save(function(err) {
                            if (err)
                                throw err;

                            return done(null, newUser);

                        });
                    }
                });
            } else {
                // User logged in so link account
                var user = req.user; // pull user out of session
                // Set profile information
                user.twitter.id          = profile.id;
                user.twitter.token       = token;
                user.twitter.username    = profile.username; 
                user.twitter.displayName = profile.displayName;

                // save linked user
                user.save(function(err){
                    if(err)
                        throw err;
                    return done(null, user);
                });
            }
        });
    }));

    // =============================
    // Google Login
    // =============================

    passport.use(new GoogleStrategy({
        clientID        : configAuth.googleAuth.clientID,
        clientSecret    : configAuth.googleAuth.clientSecret,
        callbackURL     : configAuth.googleAuth.callbackURL
    },
    function (req, token, refreshToken, profile, done) {
        // make code async
        // User.findOne won't fire until we have all data from Google
        process.nextTick(function() {
            if(!req.user){
                // User not logged in so create user
                User.findOne({ 'google.id' : profile.id }, function(err, user) {
                    if(err)
                        return done(err);

                    if(user) {

                        // if user found already, return that user.
                        return done (null, user);

                    } else {
                        // if user not found, create new
                        var newUser = new User();

                        // set all of the relevant information
                        newUser.google.id   = profile.id;
                        newUser.google.token = token;
                        newUser.google.name = profile.displayName;
                        newUser.google.email = profile.emails[0].value; // get first email only

                        // save user
                        newUser.save(function(err){
                            if(err)
                                throw err;
                            return done(null, newUser);
                        });
                    };
                });
            } else {
                var user = req.user; // pull user out of session

                // set profile informaiton
                user.google.id = profile.id;
                user.google.token = token;
                user.google.name = profile.displayName;
                user.google.email = profile.emails[0].value;
            }
        });
    }));
    
}; // end exports passport