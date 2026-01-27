using FreshFarmMarket;
using FreshFarmMarket.Entities;
using FreshFarmMarket.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Resend;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllersWithViews();
builder.Services.AddDbContext<AuthDbContext>();

// Configure Data Protection for credit card encryption
builder
    .Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(builder.Environment.ContentRootPath, "keys")))
    .SetApplicationName("FreshFarmMarket");

// Configure Identity with security settings
builder
    .Services.AddIdentity<User, IdentityRole>(options =>
    {
        // Password settings
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequiredLength = 12;

        // Lockout settings
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
        options.Lockout.MaxFailedAccessAttempts = 3;
        options.Lockout.AllowedForNewUsers = true;

        // User settings
        options.User.RequireUniqueEmail = true;
    })
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddDefaultTokenProviders();

// Configure authentication cookie with security settings
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
    options.SlidingExpiration = true;
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
});

// Configure session with security settings
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(20);
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.IsEssential = true;
});

// Add memory cache for OTP and session management
builder.Services.AddMemoryCache();

// Add HttpClient for reCAPTCHA
builder.Services.AddHttpClient();

// Configure Resend for email service
builder.Services.Configure<ResendClientOptions>(options =>
{
    options.ApiToken = builder.Configuration["Resend:ApiKey"];
});
builder.Services.AddScoped<ResendClient>();

// Register application services
builder.Services.AddScoped<IDataProtectionService, DataProtectionService>();
builder.Services.AddScoped<IAuditLogService, AuditLogService>();
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<IRecaptchaService, RecaptchaService>();
builder.Services.AddScoped<IFileUploadService, FileUploadService>();
builder.Services.AddScoped<IPasswordHistoryService, PasswordHistoryService>();
builder.Services.AddScoped<IOtpService, OtpService>();
builder.Services.AddScoped<ISessionService, SessionService>();

var app = builder.Build();

// Configure the HTTP request pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts(); // HSTS with 1 year max-age
}

// Custom middleware to remove security-sensitive headers
app.Use(
    async (context, next) =>
    {
        context.Response.Headers.Remove("X-Powered-By");
        context.Response.Headers.Remove("Server");
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        context.Response.Headers["X-Frame-Options"] = "DENY";
        context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
        context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
        context.Response.Headers["Content-Security-Policy"] =
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.google.com https://www.gstatic.com; frame-src https://www.google.com; style-src 'self' 'unsafe-inline';";
        await next();
    }
);

app.UseStatusCodePagesWithReExecute("/Home/Error", "?statusCode={0}");
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
