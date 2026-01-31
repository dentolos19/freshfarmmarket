using FreshFarmMarket.Entities;

namespace FreshFarmMarket.Models;

public class AuditLogViewModel
{
    public int Id { get; set; }
    public string Action { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string UserEmail { get; set; } = string.Empty;
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? Endpoint { get; set; }
    public AuditLogSeverity Severity { get; set; }
    public string? AdditionalData { get; set; }
}

public class AuditLogListViewModel
{
    public List<AuditLogViewModel> Logs { get; set; } = new();
    public AuditLogFilterViewModel Filter { get; set; } = new();
    public int TotalCount { get; set; }
    public int CurrentPage { get; set; } = 1;
    public int PageSize { get; set; } = 25;
    public int TotalPages => (int)Math.Ceiling((double)TotalCount / PageSize);
}

public class AuditLogFilterViewModel
{
    public string? SearchTerm { get; set; }
    public string? UserId { get; set; }
    public AuditLogSeverity? Severity { get; set; }
    public DateTime? StartDate { get; set; }
    public DateTime? EndDate { get; set; }
    public string? ActionType { get; set; }
    public int Page { get; set; } = 1;
    public int PageSize { get; set; } = 25;
}
