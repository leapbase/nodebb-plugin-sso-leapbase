'use strict';

(function (module) {
  /*
    Welcome to the SSO OAuth plugin! If you're inspecting this code, you're probably looking to
    hook up NodeBB with your existing OAuth endpoint.

    Step 1: Fill in the "constants" section below with the requisite informaton. Either the "oauth"
        or "oauth2" section needs to be filled, depending on what you set "type" to.

    Step 2: Give it a whirl. If you see the congrats message, you're doing well so far!

    Step 3: Customise the `parseUserReturn` method to normalise your user route's data return into
        a format accepted by NodeBB. Instructions are provided there. (Line 146)

    Step 4: If all goes well, you'll be able to login/register via your OAuth endpoint credentials.
  */

  const User = require.main.require('./src/user');
  const Groups = require.main.require('./src/groups');
  const db = require.main.require('./src/database');
  const authenticationController = require.main.require('./src/controllers/authentication');

  const async = require('async');
  const nconf = module.parent.require('nconf');
  const passport = module.parent.require('passport');
  const winston = module.parent.require('winston');
  
  /**
   * REMEMBER
   *   Never save your OAuth Key/Secret or OAuth2 ID/Secret pair in code! It could be published and leaked accidentally.
   *   Save it into your config.json file instead:
   *
   *   {
   *     ...
   *     "oauth": {
   *       "id": "someoauthid",
   *       "secret": "youroauthsecret"
   *     }
   *     ...
   *   }
   *
   *   ... or use environment variables instead:
   *
   *   `OAUTH__ID=someoauthid OAUTH__SECRET=youroauthsecret node app.js`
   */

  const constants = Object.freeze({
    type: 'oauth2',  // Either 'oauth' or 'oauth2'
    name: 'leapbase',  // Something unique to your OAuth provider in lowercase, like "github", or "nodebb"
    oauth: {
      requestTokenURL: '',
      accessTokenURL: '',
      userAuthorizationURL: '',
      consumerKey: '', // nconf.get('oauth:clientID'), 
      consumerSecret: '' // nconf.get('oauth:clientSecret')
    },
    oauth2: {
      authorizationURL: nconf.get('oauth:authorizationURL'), 
      tokenURL: nconf.get('oauth:tokenURL'), 
      clientID: nconf.get('oauth:clientID'), 
      clientSecret: nconf.get('oauth:clientSecret')
    },
    userRoute: nconf.get('oauth:userRoute'),
    scope: nconf.get('oauth:scope')
  });

  const OAuth = {};
  let configOk = false;
  let passportOAuth;
  let opts;

  if (!constants.name) {
    winston.error('[sso-oauth] Please specify a name for your OAuth provider (library.js:32)');
  } else if (!constants.type || (constants.type !== 'oauth' && constants.type !== 'oauth2')) {
    winston.error('[sso-oauth] Please specify an OAuth strategy to utilise');
  } else if (!constants.userRoute) {
    winston.error('[sso-oauth] User Route required');
  } else {
    configOk = true;
  }

  OAuth.getStrategy = function (strategies, callback) {
    if (configOk) {
      passportOAuth = require('passport-oauth')[constants.type === 'oauth' ? 'OAuthStrategy' : 'OAuth2Strategy'];

      if (constants.type === 'oauth') {
        // OAuth options
        opts = constants.oauth;
        opts.callbackURL = nconf.get('url') + '/auth/' + constants.name + '/callback';

        passportOAuth.Strategy.prototype.userProfile = function (token, secret, params, done) {
          this._oauth.get(constants.userRoute, token, secret, function (err, body/* , res */) {
            if (err) {
              return done(err);
            }

            try {
              var json = JSON.parse(body);
              OAuth.parseUserReturn(json, function (err, profile) {
                if (err) return done(err);
                profile.provider = constants.name;
                done(null, profile);
              });
            } catch (e) {
              done(e);
            }
          });
        };
      } else if (constants.type === 'oauth2') {
        // OAuth 2 options
        opts = constants.oauth2;
        opts.callbackURL = nconf.get('url') + '/auth/' + constants.name + '/callback';

        passportOAuth.Strategy.prototype.userProfile = function (accessToken, done) {
          this._oauth2.get(constants.userRoute, accessToken, function (err, body/* , res */) {
            if (err) {
              return done(err);
            }
            try {
              var json = JSON.parse(body);
              OAuth.parseUserReturn(json, function (err, profile) {
                if (err) return done(err);
                profile.provider = constants.name;
                done(null, profile);
              });
            } catch (e) {
              done(e);
            }
          });
        };
      }

      opts.passReqToCallback = true;

      passport.use(constants.name, new passportOAuth(opts, function (req, token, secret, profile, done) {
        OAuth.login({
          oAuthid: profile.id,
          handle: profile.username || profile.displayName,
          email: profile.emails[0].value,
          isAdmin: profile.isAdmin,
        }, function (err, user) {
          if (err) {
            return done(err);
          }
          authenticationController.onSuccessfulLogin(req, user.uid);
          done(null, user);
        });
      }));

      strategies.push({
        name: constants.name,
        url: '/auth/' + constants.name,
        callbackURL: '/auth/' + constants.name + '/callback',
        icon: 'fa-sign-in', //'fa-check-square',
        scope: (constants.scope || '').split(','),
      });

      callback(null, strategies);
    } else {
      callback(new Error('OAuth Configuration is invalid'));
    }
  };

  OAuth.parseUserReturn = function (data, callback) {
    // Alter this section to include whatever data is necessary
    // NodeBB *requires* the following: id, displayName, emails.
    // Everything else is optional.

    console.log('user data:', data);
    
    var profile = {};
    profile.id = data.username || data.email.replace(/@/, '_');
    profile.displayName = data.username || data.email;
    profile.emails = [{ value: data.email }];
    profile.isAdmin = data.roles && data.roles.indexOf('admin') >= 0; 

    console.log('profile:', profile);

    // eslint-disable-next-line
    callback(null, profile);
  };

  OAuth.login = function (payload, callback) {
    OAuth.getUidByOAuthid(payload.oAuthid, function (err, uid) {
      if (err) {
        return callback(err);
      }
      if (uid !== null) {
        // Existing User
        callback(null, {
          uid: uid,
        });
      } else {
        // New User
        var success = function (uid) {
          // Save provider-specific information to the user
          User.setUserField(uid, constants.name + 'Id', payload.oAuthid);
          db.setObjectField(constants.name + 'Id:uid', payload.oAuthid, uid);

          if (payload.isAdmin) {
            Groups.join('administrators', uid, function (err) {
              callback(err, {
                uid: uid,
              });
            });
          } else {
            callback(null, {
              uid: uid,
            });
          }
        };

        User.getUidByEmail(payload.email, function (err, uid) {
          if (err) {
            return callback(err);
          }
          if (!uid) {
            User.create({
              username: payload.handle && payload.handle.replace(/@/, '_'),
              email: payload.email,
            }, function (err, uid) {
              if (err) {
                return callback(err);
              }
              success(uid);
            });
          } else {
            success(uid); // Existing account -- merge
          }
        });
      }
    });
  };

  OAuth.getUidByOAuthid = function (oAuthid, callback) {
    db.getObjectField(constants.name + 'Id:uid', oAuthid, function (err, uid) {
      if (err) {
        return callback(err);
      }
      callback(null, uid);
    });
  };

  OAuth.deleteUserData = function (data, callback) {
    async.waterfall([
      async.apply(User.getUserField, data.uid, constants.name + 'Id'),
      function (oAuthIdToDelete, next) {
        db.deleteObjectField(constants.name + 'Id:uid', oAuthIdToDelete, next);
      },
    ], function (err) {
      if (err) {
        winston.error('[sso-oauth] Could not remove OAuthId data for uid ' + data.uid + '. Error: ' + err);
        return callback(err);
      }
      callback(null, data);
    });
  };

  // If this filter is not there, the deleteUserData function will fail when getting the oauthId for deletion.
  OAuth.whitelistFields = function (params, callback) {
    params.whitelist.push(constants.name + 'Id');
    callback(null, params);
  };

  module.exports = OAuth;
}(module));
