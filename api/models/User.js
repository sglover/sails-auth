var _ = require('lodash');
var crypto = require('crypto');

/** @module User */
module.exports = {
  attributes: {
    username: {
      type: Sequelize.STRING,
      field: 'email',
      unique: true,
      index: true,
      notNull: true
    },
    email: {
      type: Sequelize.STRING,
      isEmail: true,
      unique: true,
      index: true
    }
  },

  getGravatarUrl: function () {
    var md5 = crypto.createHash('md5');
    md5.update(this.email || '');
    return 'https://gravatar.com/avatar/'+ md5.digest('hex');
  },

  toJSON: function () {
    var user = this.toObject();
    delete user.password;
    user.gravatarUrl = this.getGravatarUrl();
    return user;
  },

  associations: function() {
    User.hasMany(Passport, {
      as: 'passports', otherKey: 'user'
    });
  },

  options: {
    autoCreatedBy: false,
    createdAt: false,
    updatedAt: false,
    tableName: 'users',
    classMethods: {},
    instanceMethods: {},
    hooks: {}
  },

  beforeCreate: function (user, next) {
    if (_.isEmpty(user.username)) {
      user.username = user.email;
    }
    next();
  },

  /**
   * Register a new User with a passport
   */
  register: function (user) {
    return new Promise(function (resolve, reject) {
      sails.services.passport.protocols.local.createUser(user, function (error, created) {
        if (error) return reject(error);

        resolve(created);
      });
    });
  }
};
