// =====================================================
//  تنظیمات اتصال سایت زیبادوز
// -----------------------------------------------------
//  حالت relay (پیش‌فرض برای GitHub Pages):
//    سایت به واسط ابری Google Apps Script وصل می‌شود و کامپیوتر شما
//    فقط با اتصال خروجی HTTPS با همان واسط همگام می‌ماند.
//    فقط ZD_RELAY را پر کنید.
//
//  حالت direct (اجرای محلی روی کامپیوتر خودتان):
//    ZD_MODE را "direct" بگذارید و ZD_API را روی سرور محلی تنظیم کنید.
// =====================================================

// آدرس Web App واسط ابری (خروجی Deploy در Apps Script):
// مثال: https://script.google.com/macros/s/AKfycb.../exec
window.ZD_RELAY = "";

// حالت اتصال: "relay" برای سایت عمومی GitHub Pages، "direct" برای اجرای محلی
"https://script.google.com/macros/s/AKfycbw5lnBx1inZ6aetntv6-z1l7zXFQKxivfvcO29NGxAaB8ixJv7HEeFPn-Wa-iSWu907Wg/exec";

// فقط در حالت direct استفاده می‌شود (در حالت relay خالی بماند):
window.ZD_API = "";
