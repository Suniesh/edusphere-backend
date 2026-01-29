module.exports = (...allowedRoles) => {
  return (req, res, next) => {
    console.log('ROLE FROM TOKEN:', req.user.role);
    console.log('ALLOWED ROLES:', allowedRoles);

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Access denied' });
    }
    next();
  };
};
