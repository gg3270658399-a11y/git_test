const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const path = require('path');

// 加载环境变量
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// 中间件配置
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// 会话配置
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret',
  resave: false,
  saveUninitialized: false
}));

// Passport 配置
app.use(passport.initialize());
app.use(passport.session());

// 数据库连接
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/icms', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('数据库连接成功'))
.catch(err => console.error('数据库连接失败:', err));

// 路由引入和使用
const indexRoutes = require('./routes/index');
const authRoutes = require('./routes/auth');
const controlRoutes = require('./routes/control');
const userRoutes = require('./routes/users');

app.use('/', indexRoutes);
app.use('/auth', authRoutes);
app.use('/control', controlRoutes);
app.use('/users', userRoutes);

// 错误处理中间件
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('发生服务器错误!');
});

// 启动服务器
app.listen(PORT, () => {
  console.log(`服务器运行在 http://localhost:${PORT}`);
});

module.exports = app;