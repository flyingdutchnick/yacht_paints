'use strict';
var crypto = require('crypto');
var _ = require('lodash');
var Sequelize = require('sequelize');

var db = require('../_db');

module.exports = db.define('user', {
    email: {
        type: Sequelize.STRING,
        allowNull: false,
        unique: true,
        validate: {
            isEmail: true
        }
    },
    password: {
        type: Sequelize.STRING
    },
    salt: {
        type: Sequelize.STRING
    },
    twitter_id: {
        type: Sequelize.STRING
    },
    facebook_id: {
        type: Sequelize.STRING
    },
    google_id: {
        type: Sequelize.STRING
    },
    firstName: {
        type: Sequelize.STRING,
        allowNull: false,
    },
    lastName: {
        type: Sequelize.STRING,
        allowNull: false

    },

    isAdmin: {
        type: Sequelize.BOOLEAN,
        defaultValue: false
    }


}, {
    instanceMethods: {
        sanitize: function() {
            return _.omit(this.toJSON(), ['password', 'salt']);
        },
        correctPassword: function(candidatePassword) {
            return this.Model.encryptPassword(candidatePassword, this.salt) === this.password;
        },
        changePassword: function(password) {
            return this.setDataValue('password', this.Model.encryptPassword(password, this.salt))
        }
    },
    classMethods: {
        generateSalt: function() {
            return crypto.randomBytes(16).toString('base64');
        },
        encryptPassword: function(plainText, salt) {
            var hash = crypto.createHash('sha1');
            hash.update(plainText);
            hash.update(salt);
            let final = hash.digest('hex')
            return final
        }
    },
    hooks: {
        beforeCreate: function(user) {
            user.salt = user.Model.generateSalt();
            user.password = user.Model.encryptPassword(user.password, user.salt);
        },
        beforeUpdate: function(user) {
            if (user.changed('password')) {
                user.salt = user.Model.generateSalt();
                user.password = user.Model.encryptPassword(user.password, user.salt);
            }
        }
    }
});
