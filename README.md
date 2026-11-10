# ZIBADOZ — فروشگاه اینترنتی کامل

## معماری

```
مرورگر کاربر
    │
    ├── GitHub Pages (رایگان) → Frontend سایت + پنل مدیریت
    │   https://USERNAME.github.io/zibadoz/
    │
    └── کامپیوتر شما (سرور) → Node.js + Express + PostgreSQL
        http://127.0.0.1:3000 یا https://zibadoz.dpdns.org
```

**GitHub Pages** فایل‌های استاتیک (HTML/CSS/JS) را میزبانی می‌کند.
**کامپیوتر شما** سرور Backend است که همه APIها و دیتابیس روی آن اجرا می‌شوند.

Frontend با خواندن `config.js` می‌داند سرور کجاست و API calls را به آن می‌فرستد.

## امکانات کامل (همه کار می‌کنند)

✅ نمایش محصولات با تصاویر
✅ دسته‌بندی‌ها و فیلتر
✅ جستجوی پیشرفته
✅ جزئیات محصول با رنگ و سایز
✅ سبد خرید با قیمت سایز
✅ ثبت سفارش (نیازمند حساب کاربری)
✅ پیگیری سفارش
✅ حساب کاربری مشتری
✅ نظرات و امتیازدهی
✅ پرسش و پاسخ
✅ علاقه‌مندی‌ها
✅ تاریخچه بازدید
✅ محصولات مرتبط
✅ بسته‌های اقتصادی
✅ کوپن تخفیف
✅ روش‌های ارسال
✅ بنرهای تبلیغاتی
✅ کمپین‌ها
✅ باشگاه مشتریان و امتیاز
✅ پنل مدیریت کامل
✅ گزارش‌های فروش

## راه‌اندازی سرور (کامپیوتر شما)

```cmd
cd C:\Users\pishro\OneDrive\Desktop\zibadoz
npm install
psql -U postgres -d zibadoz -f database\schema.sql
npm run create-admin -- admin "رمز-قوی"
npm start
```

سرور روی `http://127.0.0.1:3000` اجرا می‌شود.

## تنظیم آدرس سرور در config.js

فایل `public/config.js` را با Notepad ویرایش کنید:

```js
// آدرس محلی:
window.ZD_API = "http://127.0.0.1:3000";

// یا آدرس عمومی (با تونل):
window.ZD_API = "https://zibadoz.dpdns.org";
```

## انتشار روی GitHub

۱. Repository جدید بسازید: `zibadoz`
۲. همه فایل‌ها را push کنید
۳. Settings → Pages → Source: **GitHub Actions**
۴. آدرس نهایی: `https://USERNAME.github.io/zibadoz/`

## پنل مدیریت

پس از انتشار:
- آدرس پنل: `https://USERNAME.github.io/zibadoz/admin/`
- در صفحه ورود، آدرس سرور را وارد کنید (مثلاً `https://zibadoz.dpdns.org`)

## فایل‌های مهم

| فایل | توضیح |
|------|------|
| `public/config.js` | آدرس API سرور |
| `public/index.html` | سایت فروشگاه |
| `admin/index.html` | پنل مدیریت |
| `src/server.js` | سرور Backend |
| `database/schema.sql` | ساخت دیتابیس |
| `.github/workflows/deploy.yml` | انتشار خودکار GitHub Pages |
| `.nojekyll` | جلوگیری از پردازش Jekyll |
