const mongoose = require('mongoose');

const AuditLogSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  action: {
    type: String,
    required: true
  },
  resource_type: {
    type: String,
    enum: ['user', 'control_point', 'report', 'setting'],
    required: true
  },
  resource_id: {
    type: mongoose.Schema.Types.ObjectId
  },
  details: {
    type: Object
  },
  ip_address: {
    type: String
  },
  user_agent: {
    type: String
  },
  timestamp: {
    type: Date,
    default: Date.now
  },
  status: {
    type: String,
    enum: ['success', 'failure', 'warning'],
    default: 'success'
  }
});

module.exports = mongoose.model('AuditLog', AuditLogSchema);