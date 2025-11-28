const mongoose = require('mongoose');

const ControlPointSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  category: {
    type: String,
    required: true,
    enum: ['财务内控', '采购内控', '人事内控', '科研内控', '资产管理', '其他']
  },
  risk_level: {
    type: String,
    enum: ['高', '中', '低'],
    default: '中'
  },
  responsible_department: {
    type: String,
    required: true
  },
  responsible_person: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  control_activities: [{
    name: String,
    description: String,
    frequency: String
  }],
  monitoring_frequency: {
    type: String,
    enum: ['每日', '每周', '每月', '每季度', '每半年', '每年']
  },
  last_monitoring_date: {
    type: Date
  },
  status: {
    type: String,
    enum: ['有效', '待更新', '已过期'],
    default: '有效'
  },
  created_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  created_at: {
    type: Date,
    default: Date.now
  },
  updated_at: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('ControlPoint', ControlPointSchema);