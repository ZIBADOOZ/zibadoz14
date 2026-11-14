/* بوت محیط E2E مرورگر: PostgreSQL توکار + Backend روی 3210 با داده آزمایشی.
 * این پردازش باید زنده بماند (اجرا با run_in_background).
 */
import EmbeddedPostgres from 'embedded-postgres';
import { Client } from 'pg';
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const PGDATA = ROOT + '/pgdata-e2e';
const DB_URL = 'postgresql://postgres:testpw@127.0.0.1:5434/zibadoz';
const PORT = 3210;

const pg = new EmbeddedPostgres({
  databaseDir: PGDATA, user: 'postgres', password: 'testpw', port: 5434, persistent: true,
});
await pg.initialise();
await pg.start();
await pg.createDatabase('zibadoz');

const client = new Client({ connectionString: DB_URL });
await client.connect();
await client.query(readFileSync(ROOT + '/database/schema.sql', 'utf8'));
for (const f of ['migrate-banners', 'migrate-phase2', 'migrate-phase3', 'migrate-phase4', 'migrate-phase6']) {
  await client.query(readFileSync(ROOT + `/database/${f}.sql`, 'utf8'));
}
await client.query(`update store_settings set value='1' where key in ('shop_active','points_enabled')`);
// تصویرهای آزمایشی (JPEG مینیمال) برای بنر، بسته و محصول
const jpeg = Buffer.from([0xFF,0xD8,0xFF,0xE0,0x00,0x10,0x4A,0x46,0x49,0x46,0x00,0x01,0x02,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0xFF,0xD9]);
for (const d of ['products','banners','bundles','campaigns','receipts']) {
  try { writeFileSync(`${ROOT}/uploads/${d}/e2e.jpg`, jpeg); } catch {}
}
await client.query(`insert into categories(name,slug,sort) values ('دسته تست','e2e-cat',99) on conflict do nothing`);
const cat = (await client.query(`select id from categories where slug='e2e-cat'`)).rows[0];
await client.query(`insert into banners(title,image,category_id,is_active,sort_order) values ('بنر تست','e2e.jpg',$1,true,1)`, [cat.id]);
await client.query(`insert into product_bundles(title,description,image,bundle_price,original_price,is_active,sort_order) values ('بسته تست','بسته آزمایشی','e2e.jpg',100000,120000,true,1)`);
const p = (await client.query(`insert into products(slug,name,short_desc,description,price,category_id,stock,colors,sizes,published,featured)
  values ('e2e-bag','کیف تست مرورگر','کیف آزمایشی','توضیح',1500000,$1,10,'[]'::jsonb,'[]'::jsonb,true,true) returning id`, [cat.id])).rows[0];
await client.query(`insert into product_images(product_id,file,is_main,sort) values ($1,'e2e.jpg',true,0)`, [p.id]);
await client.end();
console.log('E2E DB READY');

const server = spawn('node', ['src/server.js'], {
  cwd: ROOT,
  env: { ...process.env, PORT: String(PORT), DATABASE_URL: DB_URL, JWT_SECRET: 'y'.repeat(48), NODE_ENV: 'development', TRUST_PROXY: '1' },
  stdio: 'inherit',
});
console.log('E2E SERVER SPAWNING on', PORT);
setInterval(() => {}, 10000); // زنده ماندن پردازش
process.on('SIGTERM', () => { try { server.kill(); pg.stop(); } catch {} process.exit(0); });
