const express = require('express');
const router = express.Router();
const ControlPoint = require('../models/ControlPoint');
const AuditLog = require('../models/AuditLog');

// 确保用户已登录的中间件
const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/auth/login');
};

// 首页路由
router.get('/', (req, res) => {
  res.render('index', { user: req.user });
});

// 仪表盘路由
router.get('/dashboard', ensureAuthenticated, async (req, res) => {
  try {
    // 获取控制点统计信息
    const totalPoints = await ControlPoint.countDocuments();
    const highRiskPoints = await ControlPoint.countDocuments({ risk_level: '高' });
    const mediumRiskPoints = await ControlPoint.countDocuments({ risk_level: '中' });
    const lowRiskPoints = await ControlPoint.countDocuments({ risk_level: '低' });
    const expiredPoints = await ControlPoint.countDocuments({ status: '已过期' });
    
    // 获取最近的控制点
    const recentPoints = await ControlPoint.find().sort({ created_at: -1 }).limit(5)
      .populate('responsible_person', 'username').populate('created_by', 'username');
    
    // 获取最近的审计日志
    const recentLogs = await AuditLog.find().sort({ timestamp: -1 }).limit(5)
      .populate('user', 'username');
    
    res.render('dashboard', {
      user: req.user,
      statistics: {
        total: totalPoints,
        highRisk: highRiskPoints,
        mediumRisk: mediumRiskPoints,
        lowRisk: lowRiskPoints,
        expired: expiredPoints
      },
      recentPoints,
      recentLogs
    });
  } catch (error) {
    console.error('获取仪表盘数据失败:', error);
    res.status(500).send('服务器错误');
  }
});

module.exports = router;