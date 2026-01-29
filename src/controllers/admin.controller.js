const db = require('../config/db');
const bcrypt = require('bcrypt');

/* ================= CREATE ADMIN ================= */

exports.createAdmin = async (req, res) => {
  try {
    const { full_name, email, phone, password, role } = req.body;

    if (!full_name || !email || !phone || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // force safety: only ADMIN unless explicitly SUPER_ADMIN
    const adminRole =
      role === 'SUPER_ADMIN' ? 'SUPER_ADMIN' : 'ADMIN';

    const [existing] = await db.query(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );

    if (existing.length > 0) {
      return res.status(409).json({ message: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await db.query(
      `
      INSERT INTO users 
        (full_name, email, phone, password, role, created_by)
      VALUES 
        (?, ?, ?, ?, ?, ?)
      `,
      [
        full_name,
        email,
        phone,
        hashedPassword,
        adminRole,
        req.user.id
      ]
    );

    await db.query(
      `
      INSERT INTO audit_logs
        (action_type, entity_type, entity_id, performed_by, performed_by_role)
      VALUES (?, ?, ?, ?, ?)
      `,
      [
        'CREATE_ADMIN',
        'USER',
        result.insertId,
        req.user.id,
        req.user.role
      ]
    );

    res.status(201).json({
      message: `${adminRole.replace('_', ' ')} created successfully`
    });
  } catch (error) {
    console.error('Create admin error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

/* ================= TEACHERS ================= */

exports.getPendingTeachers = async (req, res) => {
  try {
    const [rows] = await db.query(
      `
      SELECT 
        id,
        full_name,
        email,
        phone,
        created_at
      FROM users
      WHERE role = 'TEACHER'
        AND is_approved = 0
      ORDER BY created_at DESC
      `
    );

    res.status(200).json(rows);
  } catch (error) {
    console.error('Get pending teachers error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

exports.approveTeacher = async (req, res) => {
  try {
    const { id } = req.params;

    const [result] = await db.query(
      `
      UPDATE users
      SET is_approved = 1
      WHERE id = ? AND role = 'TEACHER'
      `,
      [id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Teacher not found' });
    }

    res.status(200).json({ message: 'Teacher approved successfully' });
  } catch (error) {
    console.error('Approve teacher error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

exports.rejectTeacher = async (req, res) => {
  try {
    const { id } = req.params;

    const [result] = await db.query(
      `
      DELETE FROM users
      WHERE id = ? AND role = 'TEACHER'
      `,
      [id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Teacher not found' });
    }

    res.status(200).json({ message: 'Teacher rejected and removed' });
  } catch (error) {
    console.error('Reject teacher error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

/* ================= LIST ADMINS ================= */

exports.listAdmins = async (req, res) => {
  try {
    const [rows] = await db.query(
      `
      SELECT
        id,
        full_name,
        email,
        role,
        created_at
      FROM users
      WHERE role IN ('ADMIN', 'SUPER_ADMIN')
        AND is_active = 1
      ORDER BY created_at DESC
      `
    );

    res.status(200).json(rows);
  } catch (error) {
    console.error('List admins error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

/* ================= DELETE ADMIN ================= */

exports.deleteAdmin = async (req, res) => {
  try {
    const adminId = Number(req.params.id);

    // prevent self-delete
    if (adminId === req.user.id) {
      return res.status(400).json({ message: 'Cannot delete your own account' });
    }

    const [rows] = await db.query(
      `SELECT * FROM users WHERE id = ? AND role IN ('ADMIN','SUPER_ADMIN')`,
      [adminId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: 'Admin not found' });
    }

    const admin = rows[0];

    if (admin.role === 'SUPER_ADMIN') {
      return res.status(403).json({ message: 'Cannot delete Super Admin' });
    }

    await db.query(
      `
      INSERT INTO deleted_users
        (original_user_id, full_name, email, phone, role, deleted_by)
      VALUES (?, ?, ?, ?, ?, ?)
      `,
      [
        admin.id,
        admin.full_name,
        admin.email,
        admin.phone,
        admin.role,
        req.user.id
      ]
    );

    await db.query(
      `UPDATE users SET is_active = 0 WHERE id = ?`,
      [adminId]
    );

    res.json({ message: 'Admin deleted successfully' });
  } catch (error) {
    console.error('Delete admin error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

/* ================= DELETED ADMINS ================= */

exports.listDeletedAdmins = async (req, res) => {
  try {
    const [rows] = await db.query(
      `
      SELECT *
      FROM deleted_users
      ORDER BY deleted_at DESC
      `
    );

    res.json(rows);
  } catch (error) {
    console.error('List deleted admins error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

exports.restoreAdmin = async (req, res) => {
  try {
    const deletedId = req.params.id;

    const [rows] = await db.query(
      `SELECT * FROM deleted_users WHERE id = ?`,
      [deletedId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: 'Deleted admin not found' });
    }

    const deleted = rows[0];

    await db.query(
      `UPDATE users SET is_active = 1 WHERE id = ?`,
      [deleted.original_user_id]
    );

    await db.query(
      `DELETE FROM deleted_users WHERE id = ?`,
      [deletedId]
    );

    res.json({ message: 'Admin restored successfully' });
  } catch (error) {
    console.error('Restore admin error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};
