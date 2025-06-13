const bcrypt = require('bcryptjs');
bcrypt.hash('securepassword', 10).then(console.log);
