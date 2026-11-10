// استفاده:  node scripts/create-admin.js نام‌کاربری رمز(حداقل ۱۰ کاراکتر)
require('dotenv').config();
const bcrypt = require('bcryptjs'), db = require('../src/db');
(async () => {
  const [u, p] = process.argv.slice(2);
  if (!u || !p || p.length < 10) { console.log('نام کاربری و رمز حداقل ۱۰ کاراکتری لازم است'); process.exit(1); }
  await db.query('insert into admin_users(username,password_hash) values($1,$2) on conflict(username) do update set password_hash=$2', [u, await bcrypt.hash(p, 12)]);
  console.log('مدیر ساخته/به‌روز شد:', u); process.exit(0);
})().catch(e => { console.error(e.message); process.exit(1); });
