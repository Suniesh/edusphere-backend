require('dotenv').config();

console.log('JWT_SECRET at startup:', process.env.JWT_SECRET);
const adminRoutes = require('./routes/admin.routes');



const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());

app.use('/api/auth', require('./routes/auth.routes'));
app.use('/api/admin', adminRoutes);


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
