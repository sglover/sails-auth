'use strict';

var _ = require('lodash');
var crypto = require('crypto');

/** @module User */
module.exports = {
  attributes: {
    id: {
      type: Sequelize.INTEGER,
      field: 'id',
      primaryKey: true,
      autoIncrement: true
    },
    username: {
      type: Sequelize.STRING,
      field: 'email',
      unique: true,
      index: true,
      notNull: true
    }
  },

  associations: function associations() {
    User.hasMany(Passport, {
      as: 'passports', otherKey: 'user'
    });
  },

  options: {
    autoCreatedBy: false,
    createdAt: 'created_at',
    updatedAt: 'updated_at',
    tableName: 'users',
    classMethods: {
      /**
       * Register a new User with a passport
       */
      register: function register(user) {
        return sails.services.passport.protocols.local.createUser(user);
      }
    },

    instanceMethods: {
      getGravatarUrl: function getGravatarUrl() {
        var md5 = crypto.createHash('md5');
        md5.update(this.email || '');
        return 'https://gravatar.com/avatar/' + md5.digest('hex');
      },

      toJSON: function toJSON() {
        var user = this.toObject();
        delete user.password;
        user.gravatarUrl = this.getGravatarUrl();
        return user;
      }
    },

    hooks: {}
  },

  beforeCreate: function beforeCreate(user, next) {
    if (_.isEmpty(user.username)) {
      user.username = user.email;
    }
    next();
  }
};