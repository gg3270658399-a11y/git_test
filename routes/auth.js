const express = require('express');
const router = express.Router();
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');

// 配置 Passport 本地策略
passport.use(new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password'
  },
  async (username, password, done) => {
    try {
      const user = await User.findOne({ username });
      if (!user) {
        return done(null, false, { message: '用户名或密码错误' });
      }
      
      const isMatch = await user.comparePassword(password);
      if (!isMatch) {
        return done(null, false, { message: '用户名或密码错误' });
      }
      
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
));

// 序列化用户
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// 反序列化用户
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

// 登录页面
router.get('/login', (req, res) => {
  const error = req.flash('error');
  res.render('auth/login', { error });
});

// 登录处理
router.post('/login', (req, res, next) => {
  passport.authenticate('local', async (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      req.flash('error', info.message);
      return res.redirect('/auth/login');
    }
    
    req.logIn(user, async (err) => {
      if (err) {
        return next(err);
      }
      
      // 记录登录日志
      try {
        await AuditLog.create({
          user: user._id,
          action: '登录系统',
          resource_type: 'user',
          ip_address: req.ip,
          user_agent: req.headers['user-agent']
        });
      } catch (logError) {
        console.error('记录登录日志失败:', logError);
      }
      
      return res.redirect('/dashboard');
    });
  })(req, res, next);
});

// 注册页面（仅管理员可见）
router.get('/register', async (req, res) => {
  if (!req.isAuthenticated() || req.user.role !== 'admin') {
    return res.redirect('/auth/login');
  }
  res.render('auth/register');
});

// 注册处理
router.post('/register', async (req, res) => {
  if (!req.isAuthenticated() || req.user.role !== 'admin') {
    return res.redirect('/auth/login');
  }
  
  const { username, email, password, confirmPassword, role, department } = req.body;
  
  // 验证密码
  if (password !== confirmPassword) {
    req.flash('error', '两次输入的密码不一致');
    return res.redirect('/auth/register');
  }
  
  try {
    // 检查用户名是否已存在
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      req.flash('error', '用户名已存在');
      return res.redirect('/auth/register');
    }
    
    // 创建新用户
    const user = await User.create({
      username,
      email,
      password,
      role: role || 'user',
      department
    });
    
    // 记录创建用户日志
    await AuditLog.create({
      user: req.user._id,
      action: '创建用户',
      resource_type: 'user',
      resource_id: user._id,
      details: { username, email, role, department }
    });
    
    req.flash('success', '用户创建成功');
    res.redirect('/users');
  } catch (error) {
    console.error('创建用户失败:', error);
    req.flash('error', '创建用户失败，请重试');
    res.redirect('/auth/register');
  }
});

// 退出登录
router.get('/logout', async (req, res) => {
  if (req.user) {
    // 记录退出日志
    try {
      await AuditLog.create({
        user: req.user._id,
        action: '退出系统',
        resource_type: 'user',
        ip_address: req.ip,
        user_agent: req.headers['user-agent']
      });
    } catch (logError) {
      console.error('记录退出日志失败:', logError);
    }
  }
  
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect('/');
  });
});

module.exports = router;