const express = require('express');
const router = express.Router();
const ControlPoint = require('../models/ControlPoint');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');

// 确保用户已登录的中间件
const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/auth/login');
};

// 确保管理员或经理权限的中间件
const ensureAdminOrManager = (req, res, next) => {
  if (req.isAuthenticated() && (req.user.role === 'admin' || req.user.role === 'manager')) {
    return next();
  }
  req.flash('error', '权限不足');
  res.redirect('/dashboard');
};

// 控制点列表页面
router.get('/', ensureAuthenticated, async (req, res) => {
  try {
    let query = {};
    // 非管理员只能查看自己部门的控制点
    if (req.user.role !== 'admin') {
      query.responsible_department = req.user.department;
    }
    
    // 应用筛选条件
    if (req.query.category) {
      query.category = req.query.category;
    }
    if (req.query.risk_level) {
      query.risk_level = req.query.risk_level;
    }
    if (req.query.status) {
      query.status = req.query.status;
    }
    
    const controlPoints = await ControlPoint.find(query)
      .populate('responsible_person', 'username')
      .populate('created_by', 'username')
      .sort({ created_at: -1 });
    
    const categories = await ControlPoint.distinct('category');
    
    res.render('control/index', {
      user: req.user,
      controlPoints,
      categories,
      filters: req.query
    });
  } catch (error) {
    console.error('获取控制点列表失败:', error);
    res.status(500).send('服务器错误');
  }
});

// 添加控制点页面
router.get('/add', ensureAdminOrManager, async (req, res) => {
  try {
    const users = await User.find().select('username department');
    res.render('control/add', { user: req.user, users });
  } catch (error) {
    console.error('获取用户列表失败:', error);
    res.status(500).send('服务器错误');
  }
});

// 添加控制点处理
router.post('/add', ensureAdminOrManager, async (req, res) => {
  try {
    const { name, description, category, risk_level, responsible_department, 
            responsible_person, control_activities, monitoring_frequency } = req.body;
    
    // 解析控制活动
    let activities = [];
    if (control_activities && Array.isArray(control_activities.name)) {
      for (let i = 0; i < control_activities.name.length; i++) {
        if (control_activities.name[i]) {
          activities.push({
            name: control_activities.name[i],
            description: control_activities.description[i] || '',
            frequency: control_activities.frequency[i] || ''
          });
        }
      }
    }
    
    const controlPoint = await ControlPoint.create({
      name,
      description,
      category,
      risk_level,
      responsible_department,
      responsible_person: responsible_person || null,
      control_activities: activities,
      monitoring_frequency
    });
    
    // 记录审计日志
    await AuditLog.create({
      user: req.user._id,
      action: '创建控制点',
      resource_type: 'control_point',
      resource_id: controlPoint._id,
      details: req.body
    });
    
    req.flash('success', '控制点创建成功');
    res.redirect('/control');
  } catch (error) {
    console.error('创建控制点失败:', error);
    req.flash('error', '创建控制点失败，请重试');
    res.redirect('/control/add');
  }
});

// 查看控制点详情
router.get('/view/:id', ensureAuthenticated, async (req, res) => {
  try {
    const controlPoint = await ControlPoint.findById(req.params.id)
      .populate('responsible_person', 'username email')
      .populate('created_by', 'username');
    
    if (!controlPoint) {
      return res.status(404).send('控制点不存在');
    }
    
    // 检查权限
    if (req.user.role !== 'admin' && controlPoint.responsible_department !== req.user.department) {
      req.flash('error', '无权查看此控制点');
      return res.redirect('/control');
    }
    
    res.render('control/view', { user: req.user, controlPoint });
  } catch (error) {
    console.error('获取控制点详情失败:', error);
    res.status(500).send('服务器错误');
  }
});

// 编辑控制点页面
router.get('/edit/:id', ensureAdminOrManager, async (req, res) => {
  try {
    const controlPoint = await ControlPoint.findById(req.params.id);
    const users = await User.find().select('username department');
    
    if (!controlPoint) {
      return res.status(404).send('控制点不存在');
    }
    
    res.render('control/edit', { user: req.user, controlPoint, users });
  } catch (error) {
    console.error('获取控制点信息失败:', error);
    res.status(500).send('服务器错误');
  }
});

// 编辑控制点处理
router.post('/edit/:id', ensureAdminOrManager, async (req, res) => {
  try {
    const { name, description, category, risk_level, responsible_department, 
            responsible_person, control_activities, monitoring_frequency, status } = req.body;
    
    // 解析控制活动
    let activities = [];
    if (control_activities && Array.isArray(control_activities.name)) {
      for (let i = 0; i < control_activities.name.length; i++) {
        if (control_activities.name[i]) {
          activities.push({
            name: control_activities.name[i],
            description: control_activities.description[i] || '',
            frequency: control_activities.frequency[i] || ''
          });
        }
      }
    }
    
    const updatedData = {
      name,
      description,
      category,
      risk_level,
      responsible_department,
      responsible_person: responsible_person || null,
      control_activities: activities,
      monitoring_frequency,
      status,
      updated_at: Date.now()
    };
    
    const controlPoint = await ControlPoint.findByIdAndUpdate(
      req.params.id, 
      updatedData, 
      { new: true }
    );
    
    if (!controlPoint) {
      return res.status(404).send('控制点不存在');
    }
    
    // 记录审计日志
    await AuditLog.create({
      user: req.user._id,
      action: '更新控制点',
      resource_type: 'control_point',
      resource_id: controlPoint._id,
      details: updatedData
    });
    
    req.flash('success', '控制点更新成功');
    res.redirect('/control');
  } catch (error) {
    console.error('更新控制点失败:', error);
    req.flash('error', '更新控制点失败，请重试');
    res.redirect(`/control/edit/${req.params.id}`);
  }
});

// 删除控制点
router.post('/delete/:id', ensureAdminOrManager, async (req, res) => {
  try {
    const controlPoint = await ControlPoint.findByIdAndDelete(req.params.id);
    
    if (!controlPoint) {
      return res.status(404).send('控制点不存在');
    }
    
    // 记录审计日志
    await AuditLog.create({
      user: req.user._id,
      action: '删除控制点',
      resource_type: 'control_point',
      resource_id: req.params.id,
      details: { name: controlPoint.name }
    });
    
    req.flash('success', '控制点删除成功');
    res.redirect('/control');
  } catch (error) {
    console.error('删除控制点失败:', error);
    req.flash('error', '删除控制点失败，请重试');
    res.redirect('/control');
  }
});

module.exports = router;