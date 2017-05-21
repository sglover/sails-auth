'use strict';

var bcrypt = require('bcryptjs');

/**
 * Hash a passport password.
 *
 * @param {Object}   password
 * @param {Function} next
 */
function hashPassword(passport, next) {
  var config = sails.config.auth.bcrypt;
  var salt = config.salt || config.rounds;
  if (passport.password) {
    bcrypt.hash(passport.password, salt, function (err, hash) {
      if (err) {
        delete passport.password;
        sails.log.error(err);
        throw err;
      }
      passport.password = hash;
      next(null, passport);
    });
  } else {
    next(null, passport);
  }
}

/**
 * Passport Model
 *
 * The Passport model handles associating authenticators with users. An authen-
 * ticator can be either local (password) or third-party (provider). A single
 * user can have multiple passports, allowing them to connect and use several
 * third-party strategies in optional conjunction with a password.
 *
 * Since an application will only need to authenticate a user once per session,
 * it makes sense to encapsulate the data specific to the authentication process
 * in a model of its own. This allows us to keep the session itself as light-
 * weight as possible as the application only needs to serialize and deserialize
 * the user, but not the authentication data, to and from the session.
 */
var Passport = {
  attributes: {
    // Required field: Protocol
    //
    // Defines the protocol to use for the passport. When employing the local
    // strategy, the protocol will be set to 'local'. When using a third-party
    // strategy, the protocol will be set to the standard used by the third-
    // party service (e.g. 'oauth', 'oauth2', 'openid').
    // TODO 'alphanumeric'
    protocol: { type: Sequelize.STRING, allowNull: false },

    // Local field: Password
    //
    // When the local strategy is employed, a password will be used as the
    // means of authentication along with either a username or an email.
    password: { type: Sequelize.STRING, minLength: 8 },
    // accessToken is used to authenticate API requests. it is generated when a
    // passport (with protocol 'local') is created for a user.
    accessToken: { type: Sequelize.STRING },

    // Provider fields: Provider, identifer and tokens
    //
    // "provider" is the name of the third-party auth service in all lowercase
    // (e.g. 'github', 'facebook') whereas "identifier" is a provider-specific
    // key, typically an ID. These two fields are used as the main means of
    // identifying a passport and tying it to a local user.
    //
    // The "tokens" field is a JSON object used in the case of the OAuth stan-
    // dards. When using OAuth 1.0, a `token` as well as a `tokenSecret` will
    // be issued by the provider. In the case of OAuth 2.0, an `accessToken`
    // and a `refreshToken` will be issued.
    provider: { type: Sequelize.STRING,
      validate: {
        is: ["^[a-z]+[0-9]+\-+$", 'i']
      }
    },
    identifier: { type: Sequelize.STRING },
    tokens: { type: Sequelize.JSON }
  },

  associations: function associations() {
    // Associations
    //
    // Associate every passport with one, and only one, user. This requires an
    // adapter compatible with associations.
    Passport.belongsTo(User, {
      foreignKey: 'user',
      as: 'user'
    });
  },

  options: {
    autoCreatedBy: false,
    createdAt: false,
    updatedAt: false,
    tableName: 'passport',
    classMethods: {},
    instanceMethods: {
      /**
       * Validate password used by the local strategy.
       *
       * @param {string}   password The password to validate
       * @param {Function} next
       */
      validatePassword: function validatePassword(password, next) {
        bcrypt.compare(password, this.password, next);
      }
    },
    hooks: {}
  },

  /**
   * Callback to be run before creating a Passport.
   *
   * @param {Object}   passport The soon-to-be-created Passport
   * @param {Function} next
   */
  beforeCreate: function beforeCreate(passport, next) {
    hashPassword(passport, next);
  },

  /**
   * Callback to be run before updating a Passport.
   *
   * @param {Object}   passport Values to be updated
   * @param {Function} next
   */
  beforeUpdate: function beforeUpdate(passport, next) {
    hashPassword(passport, next);
  }
};

module.exports = Passport;