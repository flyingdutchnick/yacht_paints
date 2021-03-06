'use strict';

var Sequelize = require('sequelize');
var db = require('../_db');

module.exports = db.define('product', {
  name: {
    type: Sequelize.STRING,
    allowNull: false

  },

  price: {
    type: Sequelize.INTEGER,
    allowNull: false
  },

  photoUrl: {
    type: Sequelize.STRING,
    defaultValue: 'https://i.vimeocdn.com/portrait/1274237_300x300'
  },

  inventory: {
    type: Sequelize.INTEGER,
    allowNull: false
  },

  description: {
    type: Sequelize.TEXT
  },

  color: {
    type: Sequelize.STRING
  }

});
