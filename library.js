'use strict';

/* globals process, require, module */

const restApiClientFactory = require('./rest-api-client');
const meta = module.parent.require('./meta');
const user = module.parent.require('./user');
const groups = module.parent.require('./groups');
const SocketPlugins = require.main.require('./src/socket.io/plugins');

const _ = module.parent.require('underscore');
const winston = module.parent.require('winston');
const async = require('async');
const db = module.parent.require('./database');
const nconf = module.parent.require('nconf');

const controllers = require('./lib/controllers');
const nbbAuthController = module.parent.require('./controllers/authentication');

/* all the user profile fields that can be passed to user.updateProfile */
const profileFields = [
  'username',
  'email',
  'fullname',
  'website',
  'location',
  'groupTitle',
  'birthday',
  'signature',
  'signature',
  'aboutme',
  'role'
];
const payloadKeys = profileFields.concat([
  'id', // the uniq identifier of that account
  'firstName', // for backwards compatibillity
  'lastName', // dto.
  'picture'
]);

const plugin = {
  restApi: null,
  ready: false,
  settings: {
    restApiUrl: undefined,
    name: 'appId',
    cookieName: 'tickertocker_auth',
    behaviour: 'trust',
    noRegistration: 'off',
    payloadParent: undefined
  }
};

payloadKeys.forEach(function (key) {
  plugin.settings[`payload:${key}`] = key;
});

plugin.init = function ({ router, middleware: hostMiddleware }, callback) {
  router.get('/admin/plugins/session-sharing', hostMiddleware.admin.buildHeader, controllers.renderAdminPage);
  router.get('/api/admin/plugins/session-sharing', controllers.renderAdminPage);

  router.get('/api/session-sharing/lookup', controllers.retrieveUser);

  plugin.reloadSettings(callback);
};

plugin.appendConfig = function (config, callback) {
  config.sessionSharing = {
    logoutRedirect: plugin.settings.logoutRedirect,
    loginOverride: plugin.settings.loginOverride
  };

  callback(null, config);
};

/* Websocket Listeners */

SocketPlugins.sessionSharing = {};

SocketPlugins.sessionSharing.showUserIds = function (socket, data, callback) {
  // Retrieve the hash and find matches
  const uids = data.uids;
  const payload = [];

  payload.length = uids.length;

  if (uids.length) {
    async.map(
      uids,
      function (uid, next) {
        db.getSortedSetRangeByScore(`${plugin.settings.name}:uid`, 0, -1, uid, uid, next);
      },
      function (err, remoteIds) {
        if (err) {
          return callback(err);
        }

        remoteIds.forEach(function (remoteId, idx) {
          payload[idx] = remoteId;
        });

        callback(null, payload);
      }
    );
  } else {
    callback(new Error('no-uids-supplied'));
  }
};

SocketPlugins.sessionSharing.findUserByRemoteId = function (socket, data, callback) {
  if (data.remoteId) {
    plugin.getUser(data.remoteId, callback);
  } else {
    callback(new Error('no-remote-id-supplied'));
  }
};

/* End Websocket Listeners */

/*
 *	Given a remoteId, show user data
 */
plugin.getUser = function (remoteId, callback) {
  async.waterfall([
    async.apply(db.sortedSetScore, `${plugin.settings.name}:uid`, remoteId),
    function (uid, next) {
      if (uid) {
        user.getUserFields(uid, ['username', 'userslug', 'picture'], next);
      } else {
        setImmediate(next);
      }
    }
  ], callback);
};

plugin.process = function (token, callback) {
  if (typeof plugin.settings.restApiUrl !== 'string' || !plugin.settings.restApiUrl.length) {
    return callback(new Error('Provide REST API URL'));
  }

  plugin.restApi = restApiClientFactory(plugin.settings.restApiUrl);
  plugin.restApi.setToken(token);

  async.waterfall([
    async.apply(verifyToken, token),
    async.apply(plugin.normalizePayload),
    async.apply(plugin.findOrCreateUser),
    async.apply(plugin.updateUserProfile),
    async.apply(plugin.verifyUser)
  ], callback);
};

function verifyToken(token, callback) {
  winston.info('[session-sharing]', 'Verify token', token);

  plugin.restApi.currentUser()
    .then(function (response) {
      callback(null, response.data.result);
    })
    .catch(function () {
      callback(new Error('token-invalid'));
    });
}

plugin.normalizePayload = function (payload, callback) {
  const userData = {};

  if (plugin.settings.payloadParent) {
    payload = payload[plugin.settings.payloadParent];
  }

  if (typeof payload !== 'object') {
    winston.warn('[session-sharing] the payload is not an object', payload);
    return callback(new Error('payload-invalid'));
  }

  payloadKeys.forEach(function (key) {
    const propName = plugin.settings[`payload:${key}`];

    if (propName) {
      userData[key] = payload[propName];
    }
  });

  if (!userData.id) {
    winston.warn('[session-sharing] No user id was given in payload');
    return callback(new Error('payload-invalid'));
  }

  userData.fullname = (userData.fullname || [userData.firstName, userData.lastName].join(' ')).trim();

  if (!userData.username) {
    userData.username = userData.fullname;
  }

  /* strip username from illegal characters */
  userData.username = userData.username.trim().replace(/[^'"\s\-.*0-9\u00BF-\u1FFF\u2C00-\uD7FF\w]+/, '-');

  if (!userData.username) {
    winston.warn('[session-sharing] No valid username could be determined');
    return callback(new Error('payload-invalid'));
  }

  winston.verbose('[session-sharing] Payload verified');
  callback(null, userData);
};

plugin.verifyUser = function (uid, callback) {
  // Check ban state of user, reject if banned
  user.isBanned(uid, function (err, banned) {
    callback(err || banned ? new Error('banned') : null, uid);
  });
};

plugin.findOrCreateUser = function (userData, callback) {
  var queries = {};
  if (userData.email && userData.email.length) {
    queries.mergeUid = async.apply(db.sortedSetScore, 'email:uid', userData.email);
  }
  queries.uid = async.apply(db.sortedSetScore, `${plugin.settings.name}:uid`, userData.id);

  async.parallel(queries, function (err, checks) {
    if (err) {
      return callback(err);
    }

    async.waterfall([
      /* check if found something to work with */
      function (next) {
        if (checks.uid && !isNaN(parseInt(checks.uid, 10))) {
          const uid = parseInt(checks.uid, 10);
          /* check if the user with the given id actually exists */
          return user.exists(uid, function (err, exists) {
            /* ignore errors, but assume the user doesn't exist  */
            if (err) {
              winston.warn('[session-sharing] Error while testing user existance', err);
              return next(null, null);
            }
            if (exists) {
              return next(null, uid);
            }
            /* reference is outdated, user got deleted */
            db.sortedSetRemove(`${plugin.settings.name}:uid`, userData.id, function (err) {
              next(err, null);
            });
          });
        }
        if (checks.mergeUid && !isNaN(parseInt(checks.mergeUid, 10))) {
          winston.info(`[session-sharing] Found user via their email, associating this id (${userData.id}) with their NodeBB account`);
          return db.sortedSetAdd(`${plugin.settings.name}:uid`, checks.mergeUid, userData.id, function (err) {
            next(err, parseInt(checks.mergeUid, 10));
          });
        }
        setImmediate(next, null, null);
      },
      /* create the user from payload if necessary */
      function (uid, next) {
        winston.debug('createUser?', !uid);
        if (!uid) {
          if (plugin.settings.noRegistration === 'on') {
            return next(new Error('no-match'));
          }
          return plugin.createUser(userData, function (err, uid) {
            next(err, uid, userData, true);
          });
        }
        setImmediate(next, null, uid, userData, false);
      }
    ], callback);
  });
};

plugin.updateUserProfile = function (uid, userData, isNewUser, callback) {
  winston.debug('consider updateProfile?', isNewUser || plugin.settings.updateProfile === 'on');

  /* even update the profile on a new account, since some fields are not initialized by NodeBB */
  if (!isNewUser && plugin.settings.updateProfile !== 'on') {
    return setImmediate(callback, null, uid);
  }

  async.waterfall([
    function (next) {
      user.getUserFields(uid, profileFields, next);
    },
    function (existingFields, next) {
      const obj = {};

      profileFields.forEach(function (field) {
        if (typeof userData[field] !== 'undefined' && existingFields[field] !== userData[field]) {
          obj[field] = userData[field];
        }
      });

      if (Object.keys(obj).length) {
        winston.debug('[session-sharing] Updating profile fields:', obj);
        obj.uid = uid;

        return user.updateProfile(uid, obj, function (err, userObj) {
          if (err) {
            winston.warn(`[session-sharing] Unable to update profile information for uid: ${uid}(${err.message})`);
          }

          // If it errors out, not that big of a deal, continue anyway.
          next(null, userObj || existingFields);
        });
      }
      setImmediate(next, null, {});
    },
    function (userObj, next) {
      if (userData.picture) {
        return db.setObjectField(`user:${uid}`, 'picture', userData.picture, next);
      }

      setImmediate(next, null);
    },
    function (next) {
      if (userData.role === 20) {
        return groups.join('administrators', uid, next);
      } else if (userData.role === 14) {
        return groups.join('Pros', uid, next);
      } else if (userData.role === 12) {
        return groups.join('Investors', uid, next);
      }

      setImmediate(next, null);
    }
  ], err => callback(err, uid));
};

plugin.createUser = function (userData, callback) {
  winston.verbose('[session-sharing] No user found, creating a new user for this login');

  user.create(_.pick(userData, profileFields), function (err, uid) {
    if (err) {
      return callback(err);
    }

    db.sortedSetAdd(`${plugin.settings.name}:uid`, uid, userData.id, function (err) {
      callback(err, uid);
    });
  });
};

plugin.addMiddleware = function (req, res, next) {
  function handleGuest(req, res, next) {
    if (
      plugin.settings.guestRedirect &&
      !req.originalUrl.startsWith(`${nconf.get('relative_path')}/login?local=1`)
    ) {
      // If a guest redirect is specified, follow it
      res.redirect(plugin.settings.guestRedirect.replace('%1', encodeURIComponent(nconf.get('url') + req.originalUrl)));
    } else if (res.locals.fullRefresh === true) {
      res.redirect(req.url);
    } else {
      next();
    }
  }

  // Only respond to page loads by guests, not api or asset calls
  const hasSession = req.hasOwnProperty('user') &&
    req.user.hasOwnProperty('uid') &&
    parseInt(req.user.uid, 10) > 0;
  const hasLoginLock = req.session.hasOwnProperty('loginLock');

  if (
    !plugin.ready || // plugin not ready
    (plugin.settings.behaviour === 'trust' && hasSession) || // user logged in + "trust" behaviour
    (plugin.settings.behaviour === 'revalidate' && hasLoginLock) ||
    req.originalUrl.startsWith(`${nconf.get('relative_path')}/api`) // api routes
  ) {
    // Let requests through under "revalidate" behaviour only if they're logging in for the first time
    delete req.session.loginLock; // remove login lock for "revalidate" logins

    return next();
  }

  if (!req.cookies[plugin.settings.cookieName] || !req.cookies[plugin.settings.cookieName].length) {
    return next();
  }

  // Hook into ip blacklist functionality in core
  if (meta.blacklist.test(req.ip)) {
    if (hasSession) {
      req.logout();
      res.locals.fullRefresh = true;
    }

    plugin.cleanup({ res });

    return handleGuest.apply(null, arguments);
  }

  if (
    Object.keys(req.cookies).length &&
    req.cookies.hasOwnProperty(plugin.settings.cookieName) &&
    req.cookies[plugin.settings.cookieName].length
  ) {
    const token = req.cookies[plugin.settings.cookieName];

    return plugin.process(token,
      function (err, uid) {
        if (err) {
          switch (err.message) {
            case 'banned':
              winston.info(`[session-sharing] uid ${uid} is banned, not logging them in`);
              next();
              break;

            case 'payload-invalid':
              winston.warn('[session-sharing] The passed-in payload was invalid and could not be processed');
              next();
              break;

            case 'token-invalid':
              winston.warn('[session-sharing] The passed-in token was invalid and could not be processed');
              plugin.cleanup({ res });
              next();
              break;

            case 'no-match':
              winston.info('[session-sharing] Payload valid, but local account not found.  Assuming guest.');
              handleGuest.call(null, req, res, next);
              break;

            default:
              winston.warn(`[session-sharing] Error encountered while parsing token: ${err.message}`);
              next();
              break;
          }

          return;
        }

        winston.verbose(`[session-sharing] Processing login for uid ${uid}, path ${req.originalUrl}`);
        req.uid = uid;
        nbbAuthController.doLogin(req, uid, function () {
          req.session.loginLock = true;
          res.redirect(req.originalUrl);
        });
      }
    );
  }

  if (hasSession) {
    // Has login session but no cookie, can assume "revalidate" behaviour
    user.isAdministrator(req.user.uid, function (err, isAdmin) {
      if (isAdmin) {
        // Admins can bypass
        return next();
      }

      req.logout();
      res.locals.fullRefresh = true;
      handleGuest(req, res, next);
    });
  } else {
    handleGuest.apply(null, arguments);
  }
};

plugin.cleanup = function (data, callback) {
  winston.verbose('[session-sharing] Clearing cookie');
  data.res.clearCookie(plugin.settings.cookieName);

  if (typeof callback !== 'function') {
    return true;
  }

  callback();
};

plugin.addAdminNavigation = function (header, callback) {
  header.plugins.push({
    route: '/plugins/session-sharing',
    icon: 'fa-user-secret',
    name: 'Session Sharing'
  });

  callback(null, header);
};

plugin.reloadSettings = function (callback) {
  meta.settings.get('session-sharing', function (err, settings) {
    if (err) {
      return callback(err);
    }

    // If "payload:parent" is found, but payloadParent is not, update the latter and delete the former
    if (!settings.payloadParent && settings['payload:parent']) {
      winston.verbose('[session-sharing] Migrating payload:parent to payloadParent');
      settings.payloadParent = settings['payload:parent'];
      db.setObjectField('settings:session-sharing', 'payloadParent', settings.payloadParent);
      db.deleteObjectField('settings:session-sharing', 'payload:parent');
    }

    if (
      !settings['payload:username'] &&
      !settings['payload:firstName'] &&
      !settings['payload:lastName'] &&
      !settings['payload:fullname']
    ) {
      settings['payload:username'] = 'username';
    }

    winston.info('[session-sharing] Settings OK');

    plugin.settings = _.defaults(_.pick(settings, Boolean), plugin.settings);
    plugin.ready = true;

    callback();
  });
};

module.exports = plugin;
