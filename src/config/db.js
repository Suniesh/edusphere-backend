const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10
});

module.exports = pool;
pool.getConnection()
  .then(conn => {
    console.log("✅ Database connected successfully");
    conn.release();
  })
  .catch(err => {
    console.error("❌ Database connection failed:", err.message);
  });
