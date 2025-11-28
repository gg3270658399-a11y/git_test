# 广东药科大学内控管理信息系统

## 项目简介

广东药科大学内控管理信息系统是一个专为高校设计的内部控制管理平台，旨在帮助学校建立健全内部控制体系，提高风险管理水平和管理效率。本系统基于Node.js和Express框架开发，提供了控制点管理、风险评估、用户权限管理、审计日志记录等核心功能。

### 系统功能特点

- **控制点管理**：全面管理各类内控控制点，包括财务、采购、人事、科研等领域
- **风险管理**：支持风险识别、评估、应对策略制定和监控
- **用户权限管理**：基于角色的访问控制，包括管理员、部门管理员、普通用户等不同角色
- **审计日志**：全面记录系统操作，提供追溯依据和审计支持
- **数据统计与分析**：实时监控内控执行情况，提供多维度统计分析
- **响应式设计**：适配不同设备，提供良好的用户体验

## 技术栈

- **后端**：Node.js + Express.js
- **数据库**：MongoDB + Mongoose ODM
- **前端**：HTML5 + CSS3 + JavaScript + Bootstrap 4
- **模板引擎**：EJS (Embedded JavaScript templates)
- **认证授权**：Passport.js + express-session
- **密码加密**：bcrypt
- **表单验证**：express-validator

## 详细实验步骤

### 步骤一：环境准备

#### 1.1 安装Node.js

1. 访问Node.js官方网站：https://nodejs.org/
2. 下载并安装最新的LTS版本（建议版本14.x或以上）
3. 安装完成后，打开命令提示符（CMD）或PowerShell，验证安装：
   ```bash
   node -v
   npm -v
   ```
   确保显示Node.js和npm的版本号

#### 1.2 安装MongoDB

1. 访问MongoDB官方网站：https://www.mongodb.com/
2. 下载并安装MongoDB Community Server
3. 安装完成后，启动MongoDB服务
   - Windows系统可通过服务管理器启动MongoDB服务
   - 或在命令提示符中执行：
     ```bash
     net start MongoDB
     ```
4. 验证MongoDB连接：
   ```bash
   mongo
   ```
   如果连接成功，将进入MongoDB shell

#### 1.3 安装Git

1. 访问Git官方网站：https://git-scm.com/
2. 下载并安装适合Windows系统的Git版本
3. 安装完成后，验证安装：
   ```bash
   git --version
   ```

### 步骤二：项目获取与初始化

#### 2.1 克隆项目

```bash
# 在GitHub上创建新的仓库后克隆（如果已有仓库）
git clone <GitHub仓库地址> guangdong-pharma-university-icms
cd guangdong-pharma-university-icms

# 或直接进入已创建的项目目录
cd e:/ty_src/git_demo
```

#### 2.2 安装项目依赖

```bash
# 安装项目所需的所有依赖包
npm install

# 安装开发依赖（用于开发环境）
npm install --save-dev nodemon
```

#### 2.3 创建环境配置文件

```bash
# 创建.env文件
copy NUL .env

# 编辑.env文件，添加以下配置（可使用记事本或其他编辑器）
```

在.env文件中添加以下内容：

```
# 服务器配置
PORT=3000

# MongoDB数据库连接地址
MONGO_URI=mongodb://localhost:27017/icms

# 会话密钥（生产环境请使用复杂的随机字符串）
SESSION_SECRET=guangdong_pharma_university_internal_control_system_2023
```

### 步骤三：项目结构分析

在进行后续操作前，先了解项目的整体结构：

```
e:/ty_src/git_demo/
├── app.js                 # 应用主入口文件
├── models/                # 数据模型目录
│   ├── User.js            # 用户模型
│   ├── ControlPoint.js    # 控制点模型
│   └── AuditLog.js        # 审计日志模型
├── routes/                # 路由目录
│   ├── index.js           # 主路由
│   ├── auth.js            # 认证路由
│   ├── control.js         # 控制点管理路由
│   └── users.js           # 用户管理路由
├── views/                 # 视图模板目录
│   ├── layout.ejs         # 布局模板
│   ├── index.ejs          # 首页
│   ├── dashboard.ejs      # 仪表盘
│   ├── auth/              # 认证相关视图
│   │   ├── login.ejs      # 登录页面
│   │   └── register.ejs   # 注册页面
│   └── control/           # 控制点管理视图
│       └── index.ejs      # 控制点列表页面
├── public/                # 静态资源目录（自动创建）
├── package.json           # 项目配置和依赖
├── .gitignore             # Git忽略文件
└── README.md              # 项目说明文档
```

### 步骤四：数据库模型说明

#### 4.1 用户模型 (models/User.js)

```javascript
// 用户模型定义了系统用户的数据结构
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, required: true, enum: ['admin', 'department', 'user'], default: 'user' },
  department: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

// 密码加密中间件
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// 密码验证方法
UserSchema.methods.matchPassword = async function(password) {
  return await bcrypt.compare(password, this.password);
};

module.exports = mongoose.model('User', UserSchema);
```

#### 4.2 控制点模型 (models/ControlPoint.js)

```javascript
// 控制点模型定义了内部控制点的数据结构
const mongoose = require('mongoose');

const ControlPointSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  category: { 
    type: String, 
    required: true, 
    enum: ['财务', '采购', '人事', '科研', '教学', '资产管理', '其他'] 
  },
  riskLevel: { 
    type: String, 
    required: true, 
    enum: ['高风险', '中风险', '低风险'] 
  },
  responsibleDepartment: { type: String, required: true },
  responsiblePerson: { type: String, required: true },
  controlActivities: { type: String, required: true },
  monitoringFrequency: { 
    type: String, 
    enum: ['每日', '每周', '每月', '每季度', '每半年', '每年'] 
  },
  lastMonitoringDate: { type: Date },
  status: { type: String, default: '正常' },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('ControlPoint', ControlPointSchema);
```

#### 4.3 审计日志模型 (models/AuditLog.js)

```javascript
// 审计日志模型记录系统操作历史
const mongoose = require('mongoose');

const AuditLogSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  username: { type: String, required: true },
  actionType: { 
    type: String, 
    required: true,
    enum: ['登录', '退出', '创建', '编辑', '删除', '查看', '导入', '导出']
  },
  resourceType: { type: String, required: true },
  resourceId: { type: String },
  details: { type: String },
  ipAddress: { type: String },
  userAgent: { type: String },
  timestamp: { type: Date, default: Date.now },
  status: { type: String, default: '成功' }
});

module.exports = mongoose.model('AuditLog', AuditLogSchema);
```

### 步骤五：应用程序主文件解析 (app.js)

```javascript
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const flash = require('connect-flash');
const path = require('path');
require('dotenv').config();

const app = express();

// 设置模板引擎
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// 中间件
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// 会话配置
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

// Passport初始化
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// 全局变量
app.use((req, res, next) => {
  res.locals.user = req.user || null;
  res.locals.success_msg = req.flash('success_msg');
  res.locals.error_msg = req.flash('error_msg');
  res.locals.error = req.flash('error');
  next();
});

// 数据库连接
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB数据库连接成功'))
.catch(err => console.log('MongoDB数据库连接失败:', err));

// 导入路由
app.use('/', require('./routes/index'));
app.use('/auth', require('./routes/auth'));
app.use('/control', require('./routes/control'));
app.use('/users', require('./routes/users'));

// 启动服务器
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`服务器运行在 http://localhost:${PORT}`);
});
```

### 步骤六：路由模块说明

#### 6.1 主路由 (routes/index.js)

```javascript
const express = require('express');
const router = express.Router();
const ControlPoint = require('../models/ControlPoint');
const AuditLog = require('../models/AuditLog');

// 验证用户是否登录的中间件
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  req.flash('error_msg', '请先登录');
  res.redirect('/auth/login');
};

// 首页路由
router.get('/', (req, res) => {
  res.render('index');
});

// 仪表盘路由
router.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    // 获取控制点统计信息
    const totalControlPoints = await ControlPoint.countDocuments();
    const highRiskPoints = await ControlPoint.countDocuments({ riskLevel: '高风险' });
    const mediumRiskPoints = await ControlPoint.countDocuments({ riskLevel: '中风险' });
    const lowRiskPoints = await ControlPoint.countDocuments({ riskLevel: '低风险' });
    
    // 获取最近的控制点和审计日志
    const recentControlPoints = await ControlPoint.find().sort({ createdAt: -1 }).limit(5);
    const recentAuditLogs = await AuditLog.find().sort({ timestamp: -1 }).limit(10);
    
    res.render('dashboard', {
      totalControlPoints,
      highRiskPoints,
      mediumRiskPoints,
      lowRiskPoints,
      recentControlPoints,
      recentAuditLogs
    });
  } catch (err) {
    console.error('获取仪表盘数据失败:', err);
    res.status(500).send('服务器错误');
  }
});

module.exports = router;
```

#### 6.2 认证路由 (routes/auth.js)

```javascript
const express = require('express');
const router = express.Router();
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');

// Passport本地策略配置
passport.use(new LocalStrategy({
  usernameField: 'username',
  passwordField: 'password'
}, async (username, password, done) => {
  try {
    const user = await User.findOne({ username });
    if (!user) {
      return done(null, false, { message: '用户名或密码错误' });
    }
    
    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return done(null, false, { message: '用户名或密码错误' });
    }
    
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

// 序列化和反序列化用户
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// 登录路由
router.get('/login', (req, res) => {
  res.render('auth/login');
});

router.post('/login', async (req, res, next) => {
  passport.authenticate('local', async (err, user, info) => {
    if (err) {
      return next(err);
    }
    
    if (!user) {
      return res.redirect('/auth/login');
    }
    
    req.logIn(user, async (err) => {
      if (err) {
        return next(err);
      }
      
      // 记录登录审计日志
      try {
        await AuditLog.create({
          user: user.id,
          username: user.username,
          actionType: '登录',
          resourceType: '用户',
          resourceId: user.id,
          details: '用户登录系统',
          ipAddress: req.ip,
          userAgent: req.headers['user-agent']
        });
      } catch (logError) {
        console.error('记录登录日志失败:', logError);
      }
      
      return res.redirect('/dashboard');
    });
  })(req, res, next);
});

// 注册路由
router.get('/register', (req, res) => {
  res.render('auth/register');
});

router.post('/register', async (req, res) => {
  const { username, email, password, confirmPassword, department, role } = req.body;
  
  try {
    // 验证密码一致性
    if (password !== confirmPassword) {
      req.flash('error_msg', '两次输入的密码不一致');
      return res.redirect('/auth/register');
    }
    
    // 检查用户名是否已存在
    let user = await User.findOne({ username });
    if (user) {
      req.flash('error_msg', '用户名已存在');
      return res.redirect('/auth/register');
    }
    
    // 检查邮箱是否已存在
    user = await User.findOne({ email });
    if (user) {
      req.flash('error_msg', '邮箱已存在');
      return res.redirect('/auth/register');
    }
    
    // 创建新用户
    user = await User.create({
      username,
      email,
      password,
      department,
      role: role || 'user'
    });
    
    req.flash('success_msg', '注册成功，请登录');
    res.redirect('/auth/login');
  } catch (err) {
    console.error('注册失败:', err);
    req.flash('error_msg', '注册失败，请重试');
    res.redirect('/auth/register');
  }
});

// 退出登录路由
router.get('/logout', async (req, res) => {
  if (req.isAuthenticated()) {
    // 记录退出登录审计日志
    try {
      await AuditLog.create({
        user: req.user.id,
        username: req.user.username,
        actionType: '退出',
        resourceType: '用户',
        resourceId: req.user.id,
        details: '用户退出系统',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });
    } catch (logError) {
      console.error('记录退出日志失败:', logError);
    }
  }
  
  req.logout();
  res.redirect('/');
});

module.exports = router;
```

#### 6.3 控制点管理路由 (routes/control.js)

```javascript
const express = require('express');
const router = express.Router();
const ControlPoint = require('../models/ControlPoint');
const AuditLog = require('../models/AuditLog');

// 验证用户是否登录的中间件
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  req.flash('error_msg', '请先登录');
  res.redirect('/auth/login');
};

// 验证用户是否有权限管理控制点
const hasControlPermission = (req, res, next) => {
  if (req.user.role === 'admin' || req.user.role === 'department') {
    return next();
  }
  req.flash('error_msg', '您没有权限执行此操作');
  res.redirect('/dashboard');
};

// 记录审计日志的辅助函数
const logAuditAction = async (req, actionType, resourceType, resourceId, details = '') => {
  try {
    await AuditLog.create({
      user: req.user.id,
      username: req.user.username,
      actionType,
      resourceType,
      resourceId,
      details,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
  } catch (logError) {
    console.error('记录审计日志失败:', logError);
  }
};

// 控制点列表路由
router.get('/', isAuthenticated, async (req, res) => {
  try {
    // 根据用户角色过滤控制点
    let query = {};
    if (req.user.role === 'department') {
      query.responsibleDepartment = req.user.department;
    }
    
    // 获取所有控制点
    const controlPoints = await ControlPoint.find(query).sort({ createdAt: -1 });
    
    // 记录查看日志
    await logAuditAction(req, '查看', '控制点列表', null, '查看控制点列表');
    
    res.render('control/index', { controlPoints });
  } catch (err) {
    console.error('获取控制点列表失败:', err);
    req.flash('error_msg', '获取控制点列表失败');
    res.redirect('/dashboard');
  }
});

// 创建控制点路由
router.get('/create', isAuthenticated, hasControlPermission, (req, res) => {
  res.render('control/create');
});

router.post('/create', isAuthenticated, hasControlPermission, async (req, res) => {
  try {
    const { 
      name, description, category, riskLevel, 
      responsibleDepartment, responsiblePerson, 
      controlActivities, monitoringFrequency 
    } = req.body;
    
    const newControlPoint = await ControlPoint.create({
      name,
      description,
      category,
      riskLevel,
      responsibleDepartment,
      responsiblePerson,
      controlActivities,
      monitoringFrequency
    });
    
    // 记录创建日志
    await logAuditAction(
      req, 
      '创建', 
      '控制点', 
      newControlPoint._id,
      `创建控制点: ${name}`
    );
    
    req.flash('success_msg', '控制点创建成功');
    res.redirect('/control');
  } catch (err) {
    console.error('创建控制点失败:', err);
    req.flash('error_msg', '创建控制点失败，请重试');
    res.redirect('/control/create');
  }
});

// 编辑控制点路由
router.get('/edit/:id', isAuthenticated, hasControlPermission, async (req, res) => {
  try {
    const controlPoint = await ControlPoint.findById(req.params.id);
    
    // 检查权限
    if (req.user.role === 'department' && controlPoint.responsibleDepartment !== req.user.department) {
      req.flash('error_msg', '您没有权限编辑此控制点');
      return res.redirect('/control');
    }
    
    res.render('control/edit', { controlPoint });
  } catch (err) {
    console.error('获取控制点详情失败:', err);
    req.flash('error_msg', '获取控制点详情失败');
    res.redirect('/control');
  }
});

router.post('/edit/:id', isAuthenticated, hasControlPermission, async (req, res) => {
  try {
    const controlPoint = await ControlPoint.findById(req.params.id);
    
    // 检查权限
    if (req.user.role === 'department' && controlPoint.responsibleDepartment !== req.user.department) {
      req.flash('error_msg', '您没有权限编辑此控制点');
      return res.redirect('/control');
    }
    
    const { 
      name, description, category, riskLevel, 
      responsibleDepartment, responsiblePerson, 
      controlActivities, monitoringFrequency 
    } = req.body;
    
    // 更新控制点
    controlPoint.name = name;
    controlPoint.description = description;
    controlPoint.category = category;
    controlPoint.riskLevel = riskLevel;
    controlPoint.responsibleDepartment = responsibleDepartment;
    controlPoint.responsiblePerson = responsiblePerson;
    controlPoint.controlActivities = controlActivities;
    controlPoint.monitoringFrequency = monitoringFrequency;
    
    await controlPoint.save();
    
    // 记录编辑日志
    await logAuditAction(
      req, 
      '编辑', 
      '控制点', 
      controlPoint._id,
      `编辑控制点: ${name}`
    );
    
    req.flash('success_msg', '控制点更新成功');
    res.redirect('/control');
  } catch (err) {
    console.error('更新控制点失败:', err);
    req.flash('error_msg', '更新控制点失败，请重试');
    res.redirect(`/control/edit/${req.params.id}`);
  }
});

// 删除控制点路由
router.get('/delete/:id', isAuthenticated, hasControlPermission, async (req, res) => {
  try {
    const controlPoint = await ControlPoint.findById(req.params.id);
    
    // 检查权限
    if (req.user.role === 'department' && controlPoint.responsibleDepartment !== req.user.department) {
      req.flash('error_msg', '您没有权限删除此控制点');
      return res.redirect('/control');
    }
    
    const pointName = controlPoint.name;
    await ControlPoint.findByIdAndDelete(req.params.id);
    
    // 记录删除日志
    await logAuditAction(
      req, 
      '删除', 
      '控制点', 
      req.params.id,
      `删除控制点: ${pointName}`
    );
    
    req.flash('success_msg', '控制点删除成功');
    res.redirect('/control');
  } catch (err) {
    console.error('删除控制点失败:', err);
    req.flash('error_msg', '删除控制点失败，请重试');
    res.redirect('/control');
  }
});

module.exports = router;
```

### 步骤七：创建管理员账户

在使用系统前，我们需要创建一个管理员账户。有两种方法：

#### 7.1 通过代码创建管理员

创建一个createAdmin.js文件：

```javascript
const mongoose = require('mongoose');
const User = require('./models/User');
require('dotenv').config();

// 连接数据库
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(async () => {
  console.log('数据库连接成功');
  
  // 创建管理员账户
  try {
    const admin = await User.create({
      username: 'admin',
      email: 'admin@example.com',
      password: 'admin123',  // 实际使用时请修改为强密码
      role: 'admin',
      department: '信息中心'
    });
    
    console.log('管理员账户创建成功:', admin.username);
  } catch (err) {
    console.error('创建管理员账户失败:', err);
  } finally {
    mongoose.connection.close();
  }
})
.catch(err => {
  console.error('数据库连接失败:', err);
});
```

运行脚本：
```bash
node createAdmin.js
```

#### 7.2 通过MongoDB Shell创建管理员

```bash
# 连接MongoDB
mongo

# 切换到项目数据库
use icms

# 创建管理员账户（密码将在应用中自动加密）
db.users.insertOne({
  "username": "admin",
  "email": "admin@example.com",
  "password": "admin123",  // 实际使用时请修改为强密码
  "role": "admin",
  "department": "信息中心",
  "createdAt": new Date()
})
```

### 步骤八：启动应用并访问

#### 8.1 启动MongoDB服务

确保MongoDB服务正在运行：
```bash
net start MongoDB
```

#### 8.2 启动应用服务器

```bash
# 开发模式启动（使用nodemon自动重启）
npm run dev

# 或生产模式启动
npm start
```

#### 8.3 访问应用

打开浏览器，访问：http://localhost:3000

### 步骤九：系统使用说明

#### 9.1 登录系统

1. 访问 http://localhost:3000/auth/login
2. 输入管理员账户：用户名admin，密码admin123
3. 点击登录按钮

#### 9.2 仪表盘功能

登录成功后，系统会自动跳转到仪表盘页面，显示：
- 控制点统计信息（总控制点、高/中/低风险点数量）
- 最近添加的控制点
- 系统操作日志

#### 9.3 控制点管理

1. 在左侧菜单点击「控制点管理」
2. 查看所有控制点列表
3. 点击「创建新控制点」按钮添加控制点
4. 使用编辑和删除按钮管理现有控制点

#### 9.4 用户管理

1. 管理员可以在左侧菜单点击「用户管理」
2. 查看所有用户列表
3. 添加、编辑或删除用户账户
4. 分配用户角色和部门

## Git操作详细步骤

### 1. 初始化Git仓库

```bash
# 进入项目目录
cd e:/ty_src/git_demo

# 检查当前目录
pwd

# 初始化Git仓库
git init
```

### 2. 配置Git用户信息

```bash
# 设置用户名
git config --global user.name "Your Name"

# 设置邮箱
git config --global user.email "your.email@example.com"
```

### 3. 创建.gitignore文件

已经创建了合适的.gitignore文件，包含以下内容：

```
# 依赖目录
node_modules/

# 环境变量文件
.env
.env.local
.env.*.local

# 日志文件
*.log
npm-debug.log*
yarn-debug.log*
yarn-error.log*
pnpm-debug.log*
lerna-debug.log*

# 编辑器目录和文件
.idea/
.vscode/
*.swp
*.swo

# 操作系统文件
Thumbs.db
.DS_Store
```

### 4. 添加文件到版本控制

```bash
# 查看当前状态
git status

# 添加所有文件
git add .

# 提交更改
git commit -m "初始化项目：广东药科大学内控管理信息系统"
```

### 5. 在GitHub上创建远程仓库

1. 访问GitHub网站并登录
2. 点击右上角的 "+" 图标，选择 "New repository"
3. 填写仓库名称：`guangdong-pharma-university-icms`
4. 选择公开或私有仓库
5. 点击 "Create repository"

### 6. 关联本地仓库与远程仓库

```bash
# 添加远程仓库地址（请替换为你的实际仓库地址）
git remote add origin https://github.com/yourusername/guangdong-pharma-university-icms.git

# 推送到远程仓库
git push -u origin master
```

### 7. 后续开发和更新步骤

每次修改代码后：

```bash
# 查看修改内容
git status

# 添加更改
git add .

# 提交更改（请填写有意义的提交信息）
git commit -m "描述你的更改内容"

# 推送到远程仓库
git push
```

### 8. 分支管理

```bash
# 创建新分支
git branch feature/new-feature

# 切换到新分支
git checkout feature/new-feature

# 完成开发后，合并到主分支
git checkout master
git merge feature/new-feature

# 推送合并后的主分支
git push

# 删除已完成的功能分支
git branch -d feature/new-feature
```

## 常见问题及解决方案

### 1. MongoDB连接失败

- 检查MongoDB服务是否已启动
- 确认MONGO_URI配置是否正确
- 查看防火墙是否阻止了MongoDB连接

### 2. 端口占用问题

如果3000端口被占用，可以修改.env文件中的PORT配置：
```
PORT=3001  # 使用其他未被占用的端口
```

### 3. 权限错误

确保用户拥有正确的角色权限，系统角色包括：
- admin: 管理员，拥有所有权限
- department: 部门管理员，可管理本部门的控制点
- user: 普通用户，只能查看控制点信息

### 4. 密码重置

管理员可以在用户管理界面重置其他用户的密码。

## 系统维护建议

1. **定期备份数据库**：建议每周至少备份一次MongoDB数据库
2. **更新依赖包**：定期运行 `npm update` 更新项目依赖
3. **监控系统日志**：定期查看审计日志，发现异常操作
4. **优化性能**：对于大量数据，可以考虑添加索引和分页功能
5. **安全加固**：定期更新密码策略，限制登录尝试次数

## 许可证

MIT License

© 2023 广东药科大学