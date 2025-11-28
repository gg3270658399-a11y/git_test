const express = require('express');
const router = express.Router();
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const bcrypt = require('bcrypt');

// 确保用户已登录的中间件
const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/auth/login');
};

// 确保管理员权限的中间件
const ensureAdmin = (req, res, next) => {
  if (req.isAuthenticated() && req.user.role === 'admin') {
    return next();
  }
  req.flash('error', '权限不足');
  res.redirect('/dashboard');
};

// 用户列表页面
router.get('/', ensureAdmin, async (req, res) => {
  try {
    let query = {};
    // 应用筛选条件
    if (req.query.department) {
      query.department = req.query.department;
    }
    if (req.query.role) {
      query.role = req.query.role;
    }
    
    const users = await User.find(query).sort({ created_at: -1 });
    const departments = await User.distinct('department');
    
    res.render('users/index', {
      user: req.user,
      users,
      departments,
      filters: req.query
    });
  } catch (error) {
    console.error('获取用户列表失败:', error);
    res.status(500).send('服务器错误');
  }
});

// 编辑用户页面
router.get('/edit/:id', ensureAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return res.status(404).send('用户不存在');
    }
    
    res.render('users/edit', { user: req.user, editUser: user });
  } catch (error) {
    console.error('获取用户信息失败:', error);
    res.status(500).send('服务器错误');
  }
});

// 编辑用户处理
router.post('/edit/:id', ensureAdmin, async (req, res) => {
  try {
    const { email, role, department } = req.body;
    
    const updatedData = {
      email,
      role,
      department,
      updated_at: Date.now()
    };
    
    // 如果提供了密码，则更新密码
    if (req.body.password) {
      const salt = await bcrypt.genSalt(10);
      updatedData.password = await bcrypt.hash(req.body.password, salt);
    }
    
    const user = await User.findByIdAndUpdate(
      req.params.id, 
      updatedData, 
      { new: true }
    );
    
    if (!user) {
      return res.status(404).send('用户不存在');
    }
    
    // 记录审计日志
    await AuditLog.create({
      user: req.user._id,
      action: '更新用户信息',
      resource_type: 'user',
      resource_id: user._id,
      details: updatedData
    });
    
    req.flash('success', '用户信息更新成功');
    res.redirect('/users');
  } catch (error) {
    console.error('更新用户信息失败:', error);
    req.flash('error', '更新用户信息失败，请重试');
    res.redirect(`/users/edit/${req.params.id}`);
  }
});

// 删除用户
router.post('/delete/:id', ensureAdmin, async (req, res) => {
  try {
    // 不允许删除自己
    if (req.params.id === req.user._id.toString()) {
      req.flash('error', '不能删除自己的账户');
      return res.redirect('/users');
    }
    
    const user = await User.findByIdAndDelete(req.params.id);
    
    if (!user) {
      return res.status(404).send('用户不存在');
    }
    
    // 记录审计日志
    await AuditLog.create({
      user: req.user._id,
      action: '删除用户',
      resource_type: 'user',
      resource_id: req.params.id,
      details: { username: user.username, email: user.email }
    });
    
    req.flash('success', '用户删除成功');
    res.redirect('/users');
  } catch (error) {
    console.error('删除用户失败:', error);
    req.flash('error', '删除用户失败，请重试');
    res.redirect('/users');
  }
});

// 用户个人资料页面
router.get('/profile', ensureAuthenticated, (req, res) => {
  res.render('users/profile', { user: req.user });
});

// 更新个人资料
router.post('/profile', ensureAuthenticated, async (req, res) => {
  try {
    const { email } = req.body;
    const updatedData = { email };
    
    // 如果提供了新密码和确认密码
    if (req.body.newPassword && req.body.confirmPassword) {
      // 验证当前密码
      const isMatch = await req.user.comparePassword(req.body.currentPassword);
      if (!isMatch) {
        req.flash('error', '当前密码错误');
        return res.redirect('/users/profile');
      }
      
      // 验证新密码和确认密码是否一致
      if (req.body.newPassword !== req.body.confirmPassword) {
        req.flash('error', '两次输入的新密码不一致');
        return res.redirect('/users/profile');
      }
      
      // 更新密码
      const salt = await bcrypt.genSalt(10);
      updatedData.password = await bcrypt.hash(req.body.newPassword, salt);
    }
    
    updatedData.updated_at = Date.now();
    
    const user = await User.findByIdAndUpdate(
      req.user._id, 
      updatedData, 
      { new: true }
    );
    
    // 更新session中的用户信息
    req.user = user;
    
    // 记录审计日志
    await AuditLog.create({
      user: req.user._id,
      action: '更新个人资料',
      resource_type: 'user',
      resource_id: user._id,
      details: updatedData
    });
    
    req.flash('success', '个人资料更新成功');
    res.redirect('/users/profile');
  } catch (error) {
    console.error('更新个人资料失败:', error);
    req.flash('error', '更新个人资料失败，请重试');
    res.redirect('/users/profile');
  }
});

module.exports = router;