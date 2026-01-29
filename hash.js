const bcrypt = require('bcrypt');

bcrypt.hash('SuperAdmin@123', 10).then(hash => {
  console.log(hash);
});
