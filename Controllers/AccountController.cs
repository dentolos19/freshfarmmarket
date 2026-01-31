using FreshFarmMarket.Entities;
using FreshFarmMarket.Models;
using FreshFarmMarket.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace FreshFarmMarket.Controllers;

public class AccountController : Controller
{
    private readonly UserManager<User> _userManager;
    private readonly SignInManager<User> _signInManager;
    private readonly IDataProtectionService _dataProtectionService;
    private readonly IFileUploadService _fileUploadService;
    private readonly IRecaptchaService _recaptchaService;
    private readonly IAuditLogService _auditLogService;
    private readonly IEmailService _emailService;
    private readonly IOtpService _otpService;
    private readonly ISessionService _sessionService;
    private readonly IPasswordHistoryService _passwordHistoryService;
    private readonly IPasswordResetService _passwordResetService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AccountController> _logger;

    public AccountController(
        UserManager<User> userManager,
        SignInManager<User> signInManager,
        IDataProtectionService dataProtectionService,
        IFileUploadService fileUploadService,
        IRecaptchaService recaptchaService,
        IAuditLogService auditLogService,
        IEmailService emailService,
        IOtpService otpService,
        ISessionService sessionService,
        IPasswordHistoryService passwordHistoryService,
        IPasswordResetService passwordResetService,
        IConfiguration configuration,
        ILogger<AccountController> logger
    )
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _dataProtectionService = dataProtectionService;
        _fileUploadService = fileUploadService;
        _recaptchaService = recaptchaService;
        _auditLogService = auditLogService;
        _emailService = emailService;
        _otpService = otpService;
        _sessionService = sessionService;
        _passwordHistoryService = passwordHistoryService;
        _passwordResetService = passwordResetService;
        _configuration = configuration;
        _logger = logger;
    }

    [HttpGet]
    public IActionResult Register()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        // Validate reCAPTCHA
        if (!await _recaptchaService.ValidateAsync(model.RecaptchaToken))
        {
            ModelState.AddModelError(string.Empty, "reCAPTCHA validation failed. Please try again.");
            return View(model);
        }

        // Check if email already exists
        var existingUser = await _userManager.FindByEmailAsync(model.Email);
        if (existingUser != null)
        {
            ModelState.AddModelError("Email", "An account with this email already exists.");
            return View(model);
        }

        // Upload photo
        if (model.Photo == null)
        {
            ModelState.AddModelError("Photo", "Profile photo is required.");
            return View(model);
        }

        var uploadResult = await _fileUploadService.UploadPhotoAsync(model.Photo);
        if (!uploadResult.Success)
        {
            ModelState.AddModelError("Photo", uploadResult.ErrorMessage ?? "Photo upload failed.");
            return View(model);
        }

        // Encrypt credit card number
        var encryptedCreditCard = _dataProtectionService.Encrypt(model.CreditCardNumber);

        var user = new User
        {
            UserName = model.Email,
            Email = model.Email,
            FullName = model.FullName,
            Gender = model.Gender,
            MobileNumber = model.MobileNumber,
            DeliveryAddress = model.DeliveryAddress,
            CreditCardNumber = encryptedCreditCard,
            PhotoUrl = uploadResult.FilePath!,
            AboutMe = model.AboutMe,
            LastPasswordChangedAt = DateTime.UtcNow,
            EmailConfirmed = true,
        };

        var result = await _userManager.CreateAsync(user, model.Password);

        if (result.Succeeded)
        {
            // Add password to history
            var hashedPassword = _userManager.PasswordHasher.HashPassword(user, model.Password);
            await _passwordHistoryService.AddPasswordToHistoryAsync(user.Id, hashedPassword);

            await _auditLogService.LogRegistrationAsync(user.Id);
            _logger.LogInformation("User {Email} registered successfully", model.Email);
            TempData["SuccessMessage"] = "Registration successful! Please login.";
            return RedirectToAction("Login");
        }

        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }

        return View(model);
    }

    [HttpGet]
    public IActionResult Login(string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        // Validate reCAPTCHA
        if (!await _recaptchaService.ValidateAsync(model.RecaptchaToken))
        {
            var tempUser = await _userManager.FindByEmailAsync(model.Email);
            if (tempUser != null)
            {
                await _auditLogService.LogRecaptchaFailedAsync(tempUser.Id);
            }
            ModelState.AddModelError(string.Empty, "reCAPTCHA validation failed. Please try again.");
            return View(model);
        }

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View(model);
        }

        // Check if account is locked out
        if (await _userManager.IsLockedOutAsync(user))
        {
            var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
            var remainingTime = lockoutEnd?.Subtract(DateTimeOffset.UtcNow);
            ModelState.AddModelError(
                string.Empty,
                $"Account is locked. Please try again in {remainingTime?.Minutes ?? 10} minutes."
            );
            return View(model);
        }

        // Verify password
        var passwordValid = await _userManager.CheckPasswordAsync(user, model.Password);
        if (!passwordValid)
        {
            await _userManager.AccessFailedAsync(user);
            await _auditLogService.LogLoginFailedAsync(user.Id);

            if (await _userManager.IsLockedOutAsync(user))
            {
                await _auditLogService.LogAccountLockedAsync(user.Id);
                ModelState.AddModelError(
                    string.Empty,
                    "Account has been locked due to multiple failed login attempts. Please try again in 10 minutes."
                );
            }
            else
            {
                var remainingAttempts = 3 - await _userManager.GetAccessFailedCountAsync(user);
                ModelState.AddModelError(
                    string.Empty,
                    $"Invalid login attempt. {remainingAttempts} attempts remaining before lockout."
                );
            }

            return View(model);
        }

        // Generate and send OTP for 2FA
        var otp = _otpService.GenerateOtp(model.Email);
        await _emailService.SendOtpAsync(model.Email, otp);
        await _auditLogService.LogOtpGeneratedAsync(user.Id);

        // Store email in TempData for OTP verification
        TempData["OtpEmail"] = model.Email;
        TempData["RememberMe"] = model.RememberMe;
        TempData["ReturnUrl"] = returnUrl;

        _logger.LogInformation("OTP sent to {Email} for 2FA", model.Email);
        return RedirectToAction("VerifyOtp");
    }

    [HttpGet]
    public IActionResult VerifyOtp()
    {
        var email = TempData["OtpEmail"] as string;
        if (string.IsNullOrEmpty(email))
        {
            return RedirectToAction("Login");
        }

        // Keep TempData for POST
        TempData.Keep("OtpEmail");
        TempData.Keep("RememberMe");
        TempData.Keep("ReturnUrl");

        return View(new VerifyOtpViewModel { Email = email });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyOtp(VerifyOtpViewModel model)
    {
        var email = TempData["OtpEmail"] as string;
        var rememberMe = TempData["RememberMe"] as bool? ?? false;
        var returnUrl = TempData["ReturnUrl"] as string;

        if (string.IsNullOrEmpty(email))
        {
            return RedirectToAction("Login");
        }

        if (!ModelState.IsValid)
        {
            TempData["OtpEmail"] = email;
            TempData["RememberMe"] = rememberMe;
            TempData["ReturnUrl"] = returnUrl;
            model.Email = email;
            return View(model);
        }

        // Validate OTP
        if (!_otpService.ValidateOtp(email, model.Otp))
        {
            var failedUser = await _userManager.FindByEmailAsync(email);
            if (failedUser != null)
            {
                await _auditLogService.LogOtpFailedAsync(failedUser.Id);
            }
            ModelState.AddModelError(string.Empty, "Invalid or expired OTP. Please try again.");
            TempData["OtpEmail"] = email;
            TempData["RememberMe"] = rememberMe;
            TempData["ReturnUrl"] = returnUrl;
            model.Email = email;
            return View(model);
        }

        // Invalidate OTP after successful use
        _otpService.InvalidateOtp(email);

        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return RedirectToAction("Login");
        }

        await _auditLogService.LogOtpVerifiedAsync(user.Id);

        // Check if password has expired (maximum password age policy)
        var maxPasswordAgeDays = _configuration.GetValue<int>("PasswordPolicy:MaxPasswordAgeDays", 90);
        if (user.LastPasswordChangedAt.HasValue)
        {
            var daysSincePasswordChange = (DateTime.UtcNow - user.LastPasswordChangedAt.Value).Days;
            if (daysSincePasswordChange > maxPasswordAgeDays)
            {
                // Store email and session data for force password change
                TempData["ForceChangeEmail"] = email;
                TempData["RememberMe"] = rememberMe;
                TempData["ReturnUrl"] = returnUrl;
                TempData["DaysOverdue"] = daysSincePasswordChange - maxPasswordAgeDays;

                _logger.LogWarning(
                    "User {Email} password has expired ({Days} days old)",
                    email,
                    daysSincePasswordChange
                );
                return RedirectToAction("ForceChangePassword");
            }
        }

        // Check for existing active session (concurrent login detection)
        if (!string.IsNullOrEmpty(user.CurrentSessionId))
        {
            if (_sessionService.ValidateSession(user.Id, user.CurrentSessionId))
            {
                // Invalidate previous session
                _sessionService.InvalidateSession(user.Id);
                await _auditLogService.LogConcurrentLoginAsync(user.Id);
                _logger.LogWarning("Concurrent login detected for user {Email}. Previous session invalidated.", email);
            }
        }

        // Generate new session ID
        var sessionId = _sessionService.GenerateSessionId();
        user.CurrentSessionId = sessionId;
        await _userManager.UpdateAsync(user);
        _sessionService.StoreSession(user.Id, sessionId);

        // Reset access failed count
        await _userManager.ResetAccessFailedCountAsync(user);

        // Sign in the user
        await _signInManager.SignInAsync(user, rememberMe);

        // Store session ID in session for validation
        HttpContext.Session.SetString("SessionId", sessionId);

        await _auditLogService.LogLoginSuccessAsync(user.Id);
        _logger.LogInformation("User {Email} logged in successfully", email);

        if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }

        return RedirectToAction("Index", "Home");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user != null)
        {
            // Invalidate session
            _sessionService.InvalidateSession(user.Id);
            user.CurrentSessionId = null;
            await _userManager.UpdateAsync(user);

            await _auditLogService.LogLogoutAsync(user.Id);
        }

        await _signInManager.SignOutAsync();
        HttpContext.Session.Clear();

        _logger.LogInformation("User logged out");
        return RedirectToAction("Login");
    }

    [HttpGet]
    [Authorize]
    public IActionResult ChangePassword()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return RedirectToAction("Login");
        }

        // Check minimum password age
        var minPasswordAgeMinutes = _configuration.GetValue<int>("PasswordPolicy:MinPasswordAgeMinutes", 5);
        if (user.LastPasswordChangedAt.HasValue)
        {
            var timeSinceLastChange = DateTime.UtcNow - user.LastPasswordChangedAt.Value;
            if (timeSinceLastChange.TotalMinutes < minPasswordAgeMinutes)
            {
                var remainingMinutes = minPasswordAgeMinutes - (int)timeSinceLastChange.TotalMinutes;
                ModelState.AddModelError(
                    string.Empty,
                    $"You can only change your password once every {minPasswordAgeMinutes} minutes. Please wait {remainingMinutes} more minute(s)."
                );
                return View(model);
            }
        }

        // Check password history (prevent reuse of last 2 passwords)
        if (await _passwordHistoryService.IsPasswordInHistoryAsync(user.Id, model.NewPassword, _userManager))
        {
            ModelState.AddModelError(
                string.Empty,
                "You cannot reuse any of your last 2 passwords. Please choose a different password."
            );
            return View(model);
        }

        // Change password
        var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View(model);
        }

        // Add new password to history
        var hashedPassword = _userManager.PasswordHasher.HashPassword(user, model.NewPassword);
        await _passwordHistoryService.AddPasswordToHistoryAsync(user.Id, hashedPassword);

        // Update last password changed timestamp
        user.LastPasswordChangedAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        await _auditLogService.LogPasswordChangeAsync(user.Id);

        // Sign out and require re-login
        await _signInManager.SignOutAsync();
        HttpContext.Session.Clear();

        TempData["SuccessMessage"] = "Password changed successfully! Please login with your new password.";
        return RedirectToAction("Login");
    }

    [HttpGet]
    public IActionResult ForceChangePassword()
    {
        var email = TempData["ForceChangeEmail"] as string;
        if (string.IsNullOrEmpty(email))
        {
            return RedirectToAction("Login");
        }

        // Keep TempData for POST
        TempData.Keep("ForceChangeEmail");
        TempData.Keep("RememberMe");
        TempData.Keep("ReturnUrl");

        var daysOverdue = TempData["DaysOverdue"] as int?;
        TempData.Keep("DaysOverdue");

        return View(new ForceChangePasswordViewModel { DaysOverdue = daysOverdue });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ForceChangePassword(ForceChangePasswordViewModel model)
    {
        var email = TempData["ForceChangeEmail"] as string;
        var rememberMe = TempData["RememberMe"] as bool? ?? false;
        var returnUrl = TempData["ReturnUrl"] as string;

        if (string.IsNullOrEmpty(email))
        {
            return RedirectToAction("Login");
        }

        if (!ModelState.IsValid)
        {
            TempData["ForceChangeEmail"] = email;
            TempData["RememberMe"] = rememberMe;
            TempData["ReturnUrl"] = returnUrl;
            TempData["DaysOverdue"] = model.DaysOverdue;
            return View(model);
        }

        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return RedirectToAction("Login");
        }

        // Verify current password
        if (!await _userManager.CheckPasswordAsync(user, model.CurrentPassword))
        {
            ModelState.AddModelError("CurrentPassword", "Current password is incorrect.");
            TempData["ForceChangeEmail"] = email;
            TempData["RememberMe"] = rememberMe;
            TempData["ReturnUrl"] = returnUrl;
            TempData["DaysOverdue"] = model.DaysOverdue;
            return View(model);
        }

        // Check password history
        if (await _passwordHistoryService.IsPasswordInHistoryAsync(user.Id, model.NewPassword, _userManager))
        {
            ModelState.AddModelError(
                "NewPassword",
                "You cannot reuse any of your last 2 passwords. Please choose a different password."
            );
            TempData["ForceChangeEmail"] = email;
            TempData["RememberMe"] = rememberMe;
            TempData["ReturnUrl"] = returnUrl;
            TempData["DaysOverdue"] = model.DaysOverdue;
            return View(model);
        }

        // Change password
        var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            TempData["ForceChangeEmail"] = email;
            TempData["RememberMe"] = rememberMe;
            TempData["ReturnUrl"] = returnUrl;
            TempData["DaysOverdue"] = model.DaysOverdue;
            return View(model);
        }

        // Add new password to history
        var hashedPassword = _userManager.PasswordHasher.HashPassword(user, model.NewPassword);
        await _passwordHistoryService.AddPasswordToHistoryAsync(user.Id, hashedPassword);

        // Update last password changed timestamp
        user.LastPasswordChangedAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        await _auditLogService.LogAsync(
            user.Id,
            "Password changed (forced due to expiry)",
            Entities.AuditLogSeverity.Warning
        );
        _logger.LogInformation("User {Email} completed forced password change", email);

        // Now proceed with normal login flow
        // Check for existing active session
        if (!string.IsNullOrEmpty(user.CurrentSessionId))
        {
            if (_sessionService.ValidateSession(user.Id, user.CurrentSessionId))
            {
                _sessionService.InvalidateSession(user.Id);
                _logger.LogWarning("Concurrent login detected for user {Email}. Previous session invalidated.", email);
            }
        }

        // Generate new session ID
        var sessionId = _sessionService.GenerateSessionId();
        user.CurrentSessionId = sessionId;
        await _userManager.UpdateAsync(user);
        _sessionService.StoreSession(user.Id, sessionId);

        // Reset access failed count
        await _userManager.ResetAccessFailedCountAsync(user);

        // Sign in the user
        await _signInManager.SignInAsync(user, rememberMe);

        // Store session ID in session for validation
        HttpContext.Session.SetString("SessionId", sessionId);

        await _auditLogService.LogLoginSuccessAsync(user.Id);

        TempData["SuccessMessage"] = "Your password has been updated successfully!";

        if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }

        return RedirectToAction("Index", "Home");
    }

    [HttpGet]
    public IActionResult ForgotPassword()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        // Validate reCAPTCHA
        if (!await _recaptchaService.ValidateAsync(model.RecaptchaToken))
        {
            ModelState.AddModelError(string.Empty, "reCAPTCHA validation failed. Please try again.");
            return View(model);
        }

        // Always return success to prevent email enumeration
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user != null)
        {
            // Generate reset token
            var token = _passwordResetService.GenerateResetToken(model.Email);

            // Create reset URL
            var resetUrl = Url.Action(
                "ResetPassword",
                "Account",
                new { email = model.Email, token = token },
                Request.Scheme
            );

            // Send reset email
            try
            {
                await _emailService.SendPasswordResetEmailAsync(model.Email, resetUrl!);
                await _auditLogService.LogAsync(user.Id, "Password reset requested", Entities.AuditLogSeverity.Info);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send password reset email to {Email}", model.Email);
            }
        }

        TempData["SuccessMessage"] = "If an account with that email exists, a password reset link has been sent.";
        return RedirectToAction("Login");
    }

    [HttpGet]
    public IActionResult ResetPassword(string email, string token)
    {
        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(token))
        {
            TempData["ErrorMessage"] = "Invalid password reset link.";
            return RedirectToAction("Login");
        }

        var model = new ResetPasswordViewModel { Email = email, Token = token };

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        // Validate reset token
        if (!_passwordResetService.ValidateResetToken(model.Email, model.Token))
        {
            ModelState.AddModelError(string.Empty, "Invalid or expired password reset link.");
            return View(model);
        }

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            ModelState.AddModelError(string.Empty, "Invalid password reset link.");
            return View(model);
        }

        // Check password history
        if (await _passwordHistoryService.IsPasswordInHistoryAsync(user.Id, model.NewPassword, _userManager))
        {
            ModelState.AddModelError("NewPassword", "You cannot reuse any of your last 2 passwords.");
            return View(model);
        }

        // Reset password
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var result = await _userManager.ResetPasswordAsync(user, token, model.NewPassword);

        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View(model);
        }

        // Add to password history (password is now hashed in the user object)
        var updatedUser = await _userManager.FindByIdAsync(user.Id);
        if (updatedUser?.PasswordHash != null)
        {
            await _passwordHistoryService.AddPasswordToHistoryAsync(updatedUser.Id, updatedUser.PasswordHash);
        }

        // Update last password changed timestamp
        user.LastPasswordChangedAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        // Invalidate reset token
        _passwordResetService.InvalidateResetToken(model.Email);

        await _auditLogService.LogAsync(user.Id, "Password reset completed", Entities.AuditLogSeverity.Info);

        TempData["SuccessMessage"] = "Your password has been reset successfully! Please login with your new password.";
        return RedirectToAction("Login");
    }

    [HttpGet]
    public IActionResult AccessDenied()
    {
        return View();
    }
}
