const mongoose = require('mongoose');

mongoose.Promise = global.Promise

const db = {}

db.user = require('./user.model.js')
db.role = require('./role.model.js')

db.mongoose = mongoose;

// set up the roles we want to have available
db.Roles = ['user','admin']

module.exports = db
