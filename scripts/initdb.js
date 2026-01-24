const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const HMAC_SECRET = 'your-hmac-secret-key';

// 简单的密码哈希函数（与 server/index.js 保持一致）
const hashPassword = (password) => {
  return crypto.createHmac('sha256', HMAC_SECRET).update(password).digest('hex');
};

// 数据库文件路径
const dbPath = path.join(__dirname, '..', 'database.db');

// 如果数据库文件已存在，询问是否覆盖
if (fs.existsSync(dbPath)) {
  console.log('⚠️  数据库文件已存在: database.db');
  console.log('   如需重新初始化，请先删除该文件');
  process.exit(0);
}

console.log('📦 正在初始化数据库...');

// 创建数据库连接
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('❌ 无法连接数据库:', err.message);
    process.exit(1);
  }
  console.log('✅ 已连接到数据库');
});

// 启用外键约束
db.run('PRAGMA foreign_keys = ON', (err) => {
  if (err) {
    console.error('❌ 无法启用外键约束:', err.message);
  }
});

// 使用 Promise 包装数据库操作
const runSQL = (sql) => {
  return new Promise((resolve, reject) => {
    db.run(sql, (err) => {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    });
  });
};

const insertLeaveType = (name, isNotWorkday, color = '#ff9800') => {
  return new Promise((resolve, reject) => {
    db.run(
      'INSERT INTO leave_types (name, is_not_workday, color) VALUES (?, ?, ?)',
      [name, isNotWorkday, color],
      (err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      }
    );
  });
};

const insertAdminUser = () => {
  return new Promise((resolve, reject) => {
    const passwordHash = hashPassword('admin');
    db.run(
      'INSERT INTO users (name, employee_id, password_hash, shift_type, site, role, day_night) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ['Administrator', 'admin', passwordHash, 'B', 'P1', 'admin', 'D'],
      (err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      }
    );
  });
};

// 初始化数据库
(async () => {
  try {
    // 创建 leave_types 表
    await runSQL(`
      CREATE TABLE leave_types (
        leave_id     INTEGER PRIMARY KEY AUTOINCREMENT,
        name         TEXT NOT NULL UNIQUE,
        is_not_workday  BOOLEAN DEFAULT 0,
        color        TEXT DEFAULT '#ff9800',
        created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('✅ 已创建表: leave_types');

    // 创建 calendar_tags 表
    await runSQL(`
      CREATE TABLE calendar_tags (
        date          DATE PRIMARY KEY,
        is_holiday    BOOLEAN DEFAULT 0,
        shift_type    TEXT CHECK(shift_type IN ('A', 'B')),
        updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
        comment       TEXT
      );
    `);
    console.log('✅ 已创建表: calendar_tags');

    // 创建 users 表
    await runSQL(`
      CREATE TABLE users (
        user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
        name          TEXT NOT NULL,
        employee_id   TEXT NOT NULL UNIQUE,
        shift_type    TEXT CHECK(shift_type IN ('A', 'B')),
        site          TEXT CHECK(site IN ('P1', 'P2', 'P3', 'P4')),
        password_hash TEXT NOT NULL,
        role          TEXT DEFAULT 'user' CHECK(role IN ('user', 'admin')),
        created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
        day_night TEXT CHECK(day_night IN ('D', 'N'))
      );
    `);
    console.log('✅ 已创建表: users');

    // 插入管理员用户
    await insertAdminUser();
    console.log('✅ 已创建管理员用户: admin (密码: 663955)');

    // 插入默认的 leave_types 数据
    const defaultLeaveTypes = [
      ['事假', 0, '#ff9800'],
      ['病假', 0, '#f44336'],
      ['特休', 0, '#2196f3'],
      ['加班', 1, '#9c27b0'],
    ];

    for (const [name, isNotWorkday, color] of defaultLeaveTypes) {
      await insertLeaveType(name, isNotWorkday, color);
    }
    console.log('✅ 已插入默认请假类型数据');

    console.log('\n🎉 数据库初始化完成！');
    console.log(`📁 数据库文件位置: ${dbPath}`);
    
    // 关闭数据库连接
    db.close((err) => {
      if (err) {
        console.error('❌ 关闭数据库连接时出错:', err.message);
        process.exit(1);
      } else {
        console.log('✅ 数据库连接已关闭');
        process.exit(0);
      }
    });
    
  } catch (error) {
    console.error('❌ 数据库初始化失败:', error.message);
    // 如果出错，删除已创建的数据库文件
    if (fs.existsSync(dbPath)) {
      fs.unlinkSync(dbPath);
      console.log('🗑️  已清理失败的数据库文件');
    }
    db.close();
    process.exit(1);
  }
})();
