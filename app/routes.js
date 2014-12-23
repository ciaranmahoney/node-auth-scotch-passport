// app/routes.js

module.exports = function(app, passport) {


    // ******************************************
    // STANDARD ROUTES
    // ******************************************

	// ============================
	// Home Page (with login links)
	// ============================
	app.get('/', function(req, res) {
		res.render('index.ejs'); // load index.ejs file
	});

	// =============================
	// Profile Section
	// =============================
	// we want this protected so you must be logged in to visit
	// we want to use route middleware to verify this (the isLoggedIn function)

	app.get('/profile', isLoggedIn, function(req, res){
		res.render('profile.ejs', {
			user : req.user // get the user from session and pass to template
		});
	});
    // =============================
    // Logout
    // =============================
    // route for logout
    app.get('/logout', function(req, res) {
        req.logout();
        res.redirect('/');
    });

    // ******************************************
    // AUTHENTICATE ON FIRST LOGIN
    // ******************************************

    // ============================
    // Login Page
    // ============================
    
    //show login form
    app.get('/login', function (req, res) {
        
        // render the login page and pass in any flash data if it exists
        res.render('login.ejs', { message: req.flash('loginMessage') });
    });

    // process the login form
    app.post('/login', passport.authenticate('local-login', {
        successRedirect : '/profile', // redirect to secure profile section
        failureRedirect : '/login', // redirect to login page if there is an error
        failureFlash    : true // allow flash messages
    }));

    // ============================
    // Sign Up Page
    // =============================

    // show signup form
    app.get('/signup', function (req, res) {

        // render signup page and pass in any flash data if it exists
        res.render('signup.ejs', { message: req.flash('signupMessage') });
    });

    // process the signup form
    app.post('/signup', passport.authenticate('local-signup', {
        successRedirect : '/profile', // redirect to the secure profile section
        failureRedirect : '/signup', // redirect back to signup page if there is an error
        failureFlash    : true // allow flash 
    }));

    // =============================
    // Facebook Sign up - first login
    // =============================

    // route for fb auth and login
    app.get('/auth/facebook', passport.authenticate('facebook', { scope : 'email' } ));

    // handle call back after facebook has authenticated user
    app.get('/auth/facebook/callback',
        passport.authenticate('facebook', {
            successRedirect : '/profile',
            failureRedirect : '/'
        }));

    // =============================
    // Twitter Sign up - first login
    // =============================
    // route for twitter auth and login
    app.get('/auth/twitter', passport.authenticate('twitter'));

    // handle the callback after twitter has authentiated the user
    app.get('/auth/twitter/callback', 
        passport.authenticate('twitter', {
            'successRedirect'    : '/profile',
            'failureRedirect'   : '/'
        })
    );

    // =============================
    // Google Sign up - first login
    // =============================

    // route for google auth and login
    app.get('/auth/google', passport.authenticate('google', { scope : ['profile', 'email'] }));

    // the callback for after google has authenticated
    app.get('/auth/google/callback', 
        passport.authenticate('google', {
            'successRedirect' : '/profile',
            'failureRedirect' : '/'
        })
    );

    // ******************************************
    // AUTHORIZE - USER ALREADY LOGGED IN
    // CONNECT ADDITIONAL ACCOUNTS
    // ******************************************

    // =============================
    // Connect email local login
    // =============================
    // Render connect local page
    app.get('/connect/local', function(req, res) {
        res.render('connect-local.ejs', { message: req.flash('loginMessage') });
    });
    app.post('/connect/local', passport.authenticate('local-signup', {
        successRedirect : '/profile', 
        failureRedirect : '/connect/local',
        failureFlash    : true
    }));

    // =============================
    // Connect Facebook login
    // =============================
    // Send to Facebook to authenticate
    app.get('/connect/facebook', passport.authorize('facebook', { scope : 'email' }));

    // Handle callback after facebook has authorized user
    app.get('/connect/facebook/callback', 
        passport.authorize('facebook', {
            successRedirect : '/profile',
            failureRedirect : '/'
        })
    );

    // =============================
    // Connect Twitter login
    // =============================
    // Send to Twitter to authenticate
    app.get('/connect/twitter', passport.authorize('twitter'));

    // Handle callback after twitter has authorized user
    app.get('/connect/twitter/callback', 
        passport.authorize('twitter', {
            successRedirect : '/profile',
            failureRedirect : '/'
        })
    );

    // =============================
    // Connect Google login
    // =============================
    // Send to Google to authenticate
    app.get('/connect/google', passport.authorize('google', { scope : ['profile', 'email'] }));

    // Handle callback after google has authorized user
    app.get('/connect/google/callback', 
        passport.authorize('google', {
            successRedirect : '/profile',
            failureRedirect : '/'
        })
    );

    // ******************************************
    // UNLINK ACCOUNTS
    // ******************************************
    // used to unlink accounts. for social accounts, just remove the token
    // for local account, remove email and password
    // user account will stay active in case they want to reconnect in the future

    // =============================
    // Local account unlink
    // =============================
    app.get('/unlink/local', function(req, res) {
        var user = req.user;
        user.local.email = undefined;
        user.local.password = undefined;
        user.save(function(err) {
            res.redirect('/profile');
        });
    });

    // =============================
    // Facebook account unlink
    // =============================
    app.get('/unlink/facebook', function(req, res) {
        var user = req.user;
        user.facebook.token = undefined;
        user.save(function(err) {
            res.redirect('/profile');
        });
    });


    // =============================
    // Twitter account unlink
    // =============================

    app.get('/unlink/twitter', function(req, res) {
        var user = req.user;
        user.twitter.token = undefined;
        user.save(function(err) {
            res.redirect('/profile');
        });
    });

    // =============================
    // Google account unlink
    // =============================

    app.get('/unlink/google', function(req, res) {
        var user = req.user;
        user.google.token = undefined;
        user.save(function(err) {
            res.redirect('/profile');
        });
    });

}; // end module.exports for passport routes

// route middleware to make sure a user is logged in
function isLoggedIn(req, res, next) {

    // if user is authenticated in the session, carry on
    if (req.isAuthenticated())
        return next();

    // if they aren't, redirect to home page
    res.redirect('/');
};