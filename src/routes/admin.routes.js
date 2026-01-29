const express = require('express');
const router = express.Router();

const authMiddleware = require('../middleware/auth.middleware');
const roleMiddleware = require('../middleware/role.middleware');

const {
  createAdmin,
  getPendingTeachers,
  approveTeacher,
  rejectTeacher,
  listAdmins,
  deleteAdmin,
  listDeletedAdmins,
  restoreAdmin
} = require('../controllers/admin.controller');

/* ===== TEACHERS ===== */

router.get(
  '/teachers/pending',
  authMiddleware,
  roleMiddleware('ADMIN', 'SUPER_ADMIN'),
  getPendingTeachers
);

router.post(
  '/teachers/:id/approve',
  authMiddleware,
  roleMiddleware('ADMIN', 'SUPER_ADMIN'),
  approveTeacher
);

router.delete(
  '/teachers/:id/reject',
  authMiddleware,
  roleMiddleware('ADMIN', 'SUPER_ADMIN'),
  rejectTeacher
);

/* ===== ADMINS ===== */

router.post(
  '/create-admin',
  authMiddleware,
  roleMiddleware('ADMIN', 'SUPER_ADMIN'),
  createAdmin
);

router.get(
  '/list-admins',
  authMiddleware,
  roleMiddleware('ADMIN', 'SUPER_ADMIN'),
  listAdmins
);

router.delete(
  '/delete-admin/:id',
  authMiddleware,
  roleMiddleware('ADMIN', 'SUPER_ADMIN'),
  deleteAdmin
);

router.get(
  '/deleted-admins',
  authMiddleware,
  roleMiddleware('SUPER_ADMIN'),
  listDeletedAdmins
);

router.post(
  '/restore-admin/:id',
  authMiddleware,
  roleMiddleware('SUPER_ADMIN'),
  restoreAdmin
);

module.exports = router;
