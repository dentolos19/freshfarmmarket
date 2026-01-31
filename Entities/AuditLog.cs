namespace FreshFarmMarket.Entities;

public class AuditLog
{
    public int Id { get; set; }
    public required string Action { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? Endpoint { get; set; }
    public AuditLogSeverity Severity { get; set; } = AuditLogSeverity.Info;
    public string? AdditionalData { get; set; }

    // Foreign Keys
    public required string UserId { get; set; }
    public User User { get; set; } = null!;
}
