const db = require('../config/db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

/* ====================== SIGNUP ====================== */
exports.signup = async (req, res) => {
  try {
    const { full_name, email, password, phone, role } = req.body;

    if (!full_name || !email || !password || !phone || !role) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const allowedRoles = ['STUDENT', 'TEACHER'];
    if (!allowedRoles.includes(role)) {
      return res.status(400).json({ message: 'Invalid role selected' });
    }

    const [existing] = await db.query(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );

    if (existing.length > 0) {
      return res.status(409).json({ message: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const isApproved = role === 'TEACHER' ? 0 : 1;

    await db.query(
      `
      INSERT INTO users 
        (full_name, email, password, phone, role, is_approved)
      VALUES (?, ?, ?, ?, ?, ?)
      `,
      [full_name, email, hashedPassword, phone, role, isApproved]
    );

    return res.status(201).json({
      message:
        role === 'TEACHER'
          ? 'Account created. Awaiting admin approval.'
          : 'Account created successfully'
    });

  } catch (err) {
    console.error('Signup error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
};

/* ====================== LOGIN ====================== */
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    /* 1. Validate input */
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    /* 2. Fetch user */
    const [rows] = await db.query(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );

    if (rows.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const user = rows[0];

    /* 3. Block disabled accounts */
    if (user.is_active === 0) {
      return res.status(403).json({ message: 'Account disabled' });
    }

    /* 4. Verify password */
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    /* 5. Block unapproved teachers */
    if (user.role === 'TEACHER' && user.is_approved === 0) {
      return res.status(403).json({
        message: 'You are not approved yet. Please wait for admin approval.'
      });
    }

    /* 6. Generate JWT */
    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    /* 7. Success response */
    return res.status(200).json({
      token,
      user: {
        id: user.id,
        full_name: user.full_name,
        email: user.email,
        role: user.role,
        is_approved: user.is_approved
      }
    });

  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
};
