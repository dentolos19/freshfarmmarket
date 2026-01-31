using FreshFarmMarket.Entities;
using Microsoft.EntityFrameworkCore;

namespace FreshFarmMarket.Services;

public interface IAuditLogService
{
    Task LogAsync(
        string userId,
        string action,
        AuditLogSeverity severity = AuditLogSeverity.Info,
        string? additionalData = null
    );
    Task LogLoginSuccessAsync(string userId);
    Task LogLoginFailedAsync(string userId);
    Task LogLogoutAsync(string userId);
    Task LogCreditCardAccessAsync(string userId);
    Task LogPasswordChangeAsync(string userId);
    Task LogRegistrationAsync(string userId);
    Task LogOtpGeneratedAsync(string userId);
    Task LogOtpVerifiedAsync(string userId);
    Task LogOtpFailedAsync(string userId);
    Task LogAccountLockedAsync(string userId);
    Task LogConcurrentLoginAsync(string userId);
    Task LogRecaptchaFailedAsync(string userId);

    Task<(List<AuditLog> Logs, int TotalCount)> GetLogsAsync(
        string? searchTerm = null,
        string? userId = null,
        AuditLogSeverity? severity = null,
        DateTime? startDate = null,
        DateTime? endDate = null,
        string? actionType = null,
        int page = 1,
        int pageSize = 25
    );

    Task<List<AuditLog>> GetLogsByUserAsync(string userId, int count = 50);
    Task<List<string>> GetDistinctActionsAsync();
}

public class AuditLogService : IAuditLogService
{
    private readonly AuthDbContext _context;
    private readonly ILogger<AuditLogService> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AuditLogService(
        AuthDbContext context,
        ILogger<AuditLogService> logger,
        IHttpContextAccessor httpContextAccessor
    )
    {
        _context = context;
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
    }

    private string? GetClientIpAddress()
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext == null)
            return null;

        var forwardedFor = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            return forwardedFor.Split(',')[0].Trim();
        }

        return httpContext.Connection.RemoteIpAddress?.ToString();
    }

    private string? GetUserAgent()
    {
        return _httpContextAccessor.HttpContext?.Request.Headers["User-Agent"].FirstOrDefault();
    }

    private string? GetEndpoint()
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext == null)
            return null;

        var method = httpContext.Request.Method;
        var path = httpContext.Request.Path.Value;
        return $"{method} {path}";
    }

    public async Task LogAsync(
        string userId,
        string action,
        AuditLogSeverity severity = AuditLogSeverity.Info,
        string? additionalData = null
    )
    {
        var auditLog = new AuditLog
        {
            UserId = userId,
            Action = action,
            Timestamp = DateTime.UtcNow,
            IpAddress = GetClientIpAddress(),
            UserAgent = GetUserAgent(),
            Endpoint = GetEndpoint(),
            Severity = severity,
            AdditionalData = additionalData,
        };

        _context.AuditLogs.Add(auditLog);
        await _context.SaveChangesAsync();

        _logger.LogInformation(
            "Audit [{Severity}]: User {UserId} - {Action} at {Timestamp} from {IpAddress}",
            severity,
            userId,
            action,
            auditLog.Timestamp,
            auditLog.IpAddress
        );
    }

    public async Task LogLoginSuccessAsync(string userId)
    {
        await LogAsync(userId, "Login successful", AuditLogSeverity.Info);
    }

    public async Task LogLoginFailedAsync(string userId)
    {
        await LogAsync(userId, "Login failed - invalid credentials", AuditLogSeverity.Warning);
    }

    public async Task LogLogoutAsync(string userId)
    {
        await LogAsync(userId, "User logged out", AuditLogSeverity.Info);
    }

    public async Task LogCreditCardAccessAsync(string userId)
    {
        await LogAsync(userId, "Credit card data accessed/decrypted", AuditLogSeverity.Critical);
    }

    public async Task LogPasswordChangeAsync(string userId)
    {
        await LogAsync(userId, "Password changed", AuditLogSeverity.Info);
    }

    public async Task LogRegistrationAsync(string userId)
    {
        await LogAsync(userId, "User registered", AuditLogSeverity.Info);
    }

    public async Task LogOtpGeneratedAsync(string userId)
    {
        await LogAsync(userId, "OTP generated and sent", AuditLogSeverity.Info);
    }

    public async Task LogOtpVerifiedAsync(string userId)
    {
        await LogAsync(userId, "OTP verified successfully", AuditLogSeverity.Info);
    }

    public async Task LogOtpFailedAsync(string userId)
    {
        await LogAsync(userId, "OTP verification failed", AuditLogSeverity.Warning);
    }

    public async Task LogAccountLockedAsync(string userId)
    {
        await LogAsync(userId, "Account locked due to failed attempts", AuditLogSeverity.Critical);
    }

    public async Task LogConcurrentLoginAsync(string userId)
    {
        await LogAsync(userId, "Session invalidated - concurrent login detected", AuditLogSeverity.Warning);
    }

    public async Task LogRecaptchaFailedAsync(string userId)
    {
        await LogAsync(userId, "reCAPTCHA validation failed", AuditLogSeverity.Warning);
    }

    public async Task<(List<AuditLog> Logs, int TotalCount)> GetLogsAsync(
        string? searchTerm = null,
        string? userId = null,
        AuditLogSeverity? severity = null,
        DateTime? startDate = null,
        DateTime? endDate = null,
        string? actionType = null,
        int page = 1,
        int pageSize = 25
    )
    {
        var query = _context.AuditLogs.Include(a => a.User).AsQueryable();

        if (!string.IsNullOrWhiteSpace(searchTerm))
        {
            query = query.Where(a =>
                a.Action.Contains(searchTerm)
                || a.User.Email!.Contains(searchTerm)
                || (a.IpAddress != null && a.IpAddress.Contains(searchTerm))
            );
        }

        if (!string.IsNullOrWhiteSpace(userId))
        {
            query = query.Where(a => a.UserId == userId);
        }

        if (severity.HasValue)
        {
            query = query.Where(a => a.Severity == severity.Value);
        }

        if (startDate.HasValue)
        {
            query = query.Where(a => a.Timestamp >= startDate.Value);
        }

        if (endDate.HasValue)
        {
            var endOfDay = endDate.Value.Date.AddDays(1);
            query = query.Where(a => a.Timestamp < endOfDay);
        }

        if (!string.IsNullOrWhiteSpace(actionType))
        {
            query = query.Where(a => a.Action == actionType);
        }

        var totalCount = await query.CountAsync();

        var logs = await query
            .OrderByDescending(a => a.Timestamp)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        return (logs, totalCount);
    }

    public async Task<List<AuditLog>> GetLogsByUserAsync(string userId, int count = 50)
    {
        return await _context
            .AuditLogs.Include(a => a.User)
            .Where(a => a.UserId == userId)
            .OrderByDescending(a => a.Timestamp)
            .Take(count)
            .ToListAsync();
    }

    public async Task<List<string>> GetDistinctActionsAsync()
    {
        return await _context.AuditLogs.Select(a => a.Action).Distinct().OrderBy(a => a).ToListAsync();
    }
}
