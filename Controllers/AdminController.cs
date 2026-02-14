using System.Text;
using FreshFarmMarket.Entities;
using FreshFarmMarket.Models;
using FreshFarmMarket.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace FreshFarmMarket.Controllers;

[Authorize]
public class AdminController : Controller
{
    private readonly IAuditLogService _auditLogService;
    private readonly UserManager<User> _userManager;
    private readonly AuthDbContext _context;

    public AdminController(IAuditLogService auditLogService, UserManager<User> userManager, AuthDbContext context)
    {
        _auditLogService = auditLogService;
        _userManager = userManager;
        _context = context;
    }

    [HttpGet]
    public async Task<IActionResult> AuditLogs([FromQuery] AuditLogFilterViewModel filter)
    {
        filter.Page = filter.Page < 1 ? 1 : filter.Page;
        filter.PageSize = filter.PageSize < 1 ? 25 : filter.PageSize;

        var (logs, totalCount) = await _auditLogService.GetLogsAsync(
            searchTerm: filter.SearchTerm,
            userId: filter.UserId,
            severity: filter.Severity,
            startDate: filter.StartDate,
            endDate: filter.EndDate,
            actionType: filter.ActionType,
            page: filter.Page,
            pageSize: filter.PageSize
        );

        var viewModel = new AuditLogListViewModel
        {
            Logs = logs.Select(MapToViewModel).ToList(),
            Filter = filter,
            TotalCount = totalCount,
            CurrentPage = filter.Page,
            PageSize = filter.PageSize,
        };

        ViewBag.Users = await _context.Users.OrderBy(u => u.Email).Select(u => new { u.Id, u.Email }).ToListAsync();

        ViewBag.ActionTypes = await _auditLogService.GetDistinctActionsAsync();

        return View(viewModel);
    }

    [HttpGet]
    public async Task<IActionResult> ExportCsv([FromQuery] AuditLogFilterViewModel filter)
    {
        var (logs, _) = await _auditLogService.GetLogsAsync(
            searchTerm: filter.SearchTerm,
            userId: filter.UserId,
            severity: filter.Severity,
            startDate: filter.StartDate,
            endDate: filter.EndDate,
            actionType: filter.ActionType,
            page: 1,
            pageSize: 10000
        );

        var csv = new StringBuilder();
        csv.AppendLine("Id,Timestamp,User Email,Action,Severity,IP Address,User Agent,Endpoint,Additional Data");

        foreach (var log in logs)
        {
            csv.AppendLine(
                $"{log.Id},"
                + $"\"{log.Timestamp:yyyy-MM-dd HH:mm:ss}\","
                + $"\"{EscapeCsvField(log.User?.Email ?? "Unknown")}\","
                + $"\"{EscapeCsvField(log.Action)}\","
                + $"{log.Severity},"
                + $"\"{EscapeCsvField(log.IpAddress)}\","
                + $"\"{EscapeCsvField(log.UserAgent)}\","
                + $"\"{EscapeCsvField(log.Endpoint)}\","
                + $"\"{EscapeCsvField(log.AdditionalData)}\""
            );
        }

        var fileName = $"audit_logs_{DateTime.UtcNow:yyyyMMdd_HHmmss}.csv";
        return File(Encoding.UTF8.GetBytes(csv.ToString()), "text/csv", fileName);
    }

    private static string EscapeCsvField(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return "";
        return value.Replace("\"", "\"\"");
    }

    private static AuditLogViewModel MapToViewModel(AuditLog log)
    {
        return new AuditLogViewModel
        {
            Id = log.Id,
            Action = log.Action,
            Timestamp = log.Timestamp,
            UserId = log.UserId,
            UserEmail = log.User?.Email ?? "Unknown",
            IpAddress = log.IpAddress,
            UserAgent = log.UserAgent,
            Endpoint = log.Endpoint,
            Severity = log.Severity,
            AdditionalData = log.AdditionalData,
        };
    }

    [HttpGet]
    public async Task<IActionResult> UserManagement(
        string? searchTerm,
        string? statusFilter,
        int page = 1,
        int pageSize = 25
    )
    {
        page = page < 1 ? 1 : page;
        pageSize = pageSize < 1 ? 25 : pageSize;

        var query = _context.Users.AsQueryable();

        if (!string.IsNullOrWhiteSpace(searchTerm))
        {
            query = query.Where(u => u.Email!.Contains(searchTerm) || u.FullName.Contains(searchTerm));
        }

        var now = DateTimeOffset.UtcNow;

        if (!string.IsNullOrWhiteSpace(statusFilter))
        {
            if (statusFilter == "locked")
            {
                query = query.Where(u => u.LockoutEnd != null && u.LockoutEnd > now);
            }
            else if (statusFilter == "unlocked")
            {
                query = query.Where(u => u.LockoutEnd == null || u.LockoutEnd <= now);
            }
        }

        var totalCount = await query.CountAsync();

        var users = await query
            .OrderBy(u => u.Email)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(u => new UserManagementViewModel
            {
                Id = u.Id,
                Email = u.Email!,
                FullName = u.FullName,
                IsLockedOut = u.LockoutEnd != null && u.LockoutEnd > now,
                LockoutEnd = u.LockoutEnd,
                AccessFailedCount = u.AccessFailedCount,
                LastPasswordChangedAt = u.LastPasswordChangedAt,
            })
            .ToListAsync();

        var viewModel = new UserManagementListViewModel
        {
            Users = users,
            SearchTerm = searchTerm,
            StatusFilter = statusFilter,
            TotalCount = totalCount,
            CurrentPage = page,
            PageSize = pageSize,
        };

        return View(viewModel);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LockUser(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            TempData["ErrorMessage"] = "User not found.";
            return RedirectToAction("UserManagement");
        }

        var currentUser = await _userManager.GetUserAsync(User);
        if (currentUser?.Id == userId)
        {
            TempData["ErrorMessage"] = "You cannot lock your own account.";
            return RedirectToAction("UserManagement");
        }

        await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddYears(100));
        await _auditLogService.LogAsync(
            currentUser!.Id,
            $"Locked user account: {user.Email}",
            AuditLogSeverity.Warning
        );

        TempData["SuccessMessage"] = $"User {user.Email} has been locked.";
        return RedirectToAction("UserManagement");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> UnlockUser(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            TempData["ErrorMessage"] = "User not found.";
            return RedirectToAction("UserManagement");
        }

        await _userManager.SetLockoutEndDateAsync(user, null);
        await _userManager.ResetAccessFailedCountAsync(user);

        var currentUser = await _userManager.GetUserAsync(User);
        await _auditLogService.LogAsync(currentUser!.Id, $"Unlocked user account: {user.Email}", AuditLogSeverity.Info);

        TempData["SuccessMessage"] = $"User {user.Email} has been unlocked.";
        return RedirectToAction("UserManagement");
    }
}
