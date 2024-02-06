const mongoose = require('mongoose');
const { userSchema } = require('./server');

const User = mongoose.model('User', userSchema);
