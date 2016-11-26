var crypto = require('crypto');
var base64URL = require('base64url');
var SAError = require('../../../lib/error/SAError.js');

/**
 * Local Authentication Protocol
 *
 * The most widely used way for websites to authenticate users is via a username
 * and/or email as well as a password. This module provides functions both for
 * registering entirely new users, assigning passwords to already registered
 * users and validating login requesting.
 *
 * For more information on local authentication in Passport.js, check out:
 * http://passportjs.org/guide/username-password/
 */

/**
 * @param {Object}   req
 * @param {Object}   res
 * @param {Function} next
 */
exports.register = function (user, next) {
  exports.createUser(user, next);
};

exports.update = function (user, next) {
  exports.updateUser(user, next);
};

/**
 * Register a new user
 *
 * This method creates a new user from a specified email, username and password
 * and assign the newly created user a local Passport.
 *
 * @param {String}   username
 * @param {String}   email
 * @param {String}   password
 * @param {Function} next
 */
exports.createUser = function (_user) {
  var accessToken = generateToken();
  var password = _user.password;
  delete _user.password;

  return User
    .create(_user)
    .then(function(user) {
      return Passport
        .create({
          protocol: 'local',
          password: password,
          user: user.id,
          accessToken: accessToken
        })
        .then(function(passport) {
          return user;
        })
        .catch(function(err) {
          if (err.code === 'E_VALIDATION') {
            err = new SAError({ originalError: err });
          }

          return user
            .destroy()
            .then(function() {
              throw err
            });
        });
      });
};

/**
 * Update an user
 *
 * This method updates an user based on its id or username if id is not present
 * and assign the newly created user a local Passport.
 *
 * @param {String}   username
 * @param {String}   email
 * @param {String}   password
 * @param {Function} next
 */
exports.updateUser = function (_user,) {
  var password = _user.password;
  delete _user.password;

  var userFinder = _user.hasOwnProperty('id') ? { id: _user.id } : { username: _user.username };

  return User
    .findOne({ where: { userFinder }})
    .then(user => {
      // Check if password has a string to replace it
      if (!!password) {
        return Passport
          .findOne({ where: { protocol : 'local', user:user.id }})
          .then(passport => {
            passport.password = password;
            return passport
              .save({ fields: [ 'password' ] })
              .then(() => user);
          });
      } else {
        return user;
      }
    });
};

/**
 * Assign local Passport to user
 *
 * This function can be used to assign a local Passport to a user who doens't
 * have one already. This would be the case if the user registered using a
 * third-party service and therefore never set a password.
 *
 * @param {Object}   req
 * @param {Object}   res
 * @param {Function} next
 */
exports.connect = function (req, res) {
  var user     = req.user
    , password = req.param('password')
    , Passport = sails.models.passport;

  return Passport.findOrCreate({ where: { protocol: 'local', user: user.id}, defaults: { protocol: 'local', password: password, user: user.id }});
};

/**
 * Validate a login request
 *
 * Looks up a user using the supplied identifier (email or username) and then
 * attempts to find a local Passport associated with the user. If a Passport is
 * found, its password is checked against the password supplied in the form.
 *
 * @param {Object}   req
 * @param {string}   identifier
 * @param {string}   password
 * @param {Function} next
 */
exports.login = function (req, identifier, password) {
  var isEmail = validateEmail(identifier)
    , query   = {};

  if (isEmail) {
    query.email = identifier;
  }
  else {
    query.username = identifier;
  }

  User
    .findOne({ where: { query }})
    .then(user => {
      if (!user) {
        if (isEmail) {
          req.flash('error', 'Error.Passport.Email.NotFound');
        } else {
          req.flash('error', 'Error.Passport.Username.NotFound');
        }

        return false;
      } else {
        Passport
          .findOne({ where: { protocol: 'local', user: user.id} })
          .then(passport => {
            passport.validatePassword(password, function (err, res) {
              if (err) {
                throw err;
              }

              if (!res) {
                req.flash('error', 'Error.Passport.Password.Wrong');
                return false;
              } else {
                return (user, passport);
              }
            });
          });
      }
    });
};

var EMAIL_REGEX = /^((([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+(\.([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+)*)|((\x22)((((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(([\x01-\x08\x0b\x0c\x0e-\x1f\x7f]|\x21|[\x23-\x5b]|[\x5d-\x7e]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(\\([\x01-\x09\x0b\x0c\x0d-\x7f]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]))))*(((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(\x22)))@((([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))\.)+(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))$/i;

/**
 * Use validator module isEmail function
 *
 * @see <https://github.com/chriso/validator.js/blob/3.18.0/validator.js#L38>
 * @see <https://github.com/chriso/validator.js/blob/3.18.0/validator.js#L141-L143>
 */
function validateEmail (str) {
  return EMAIL_REGEX.test(str);
}

function generateToken() {
  return base64URL(crypto.randomBytes(48));
}
