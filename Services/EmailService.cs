using Resend;

namespace FreshFarmMarket.Services;

public interface IEmailService
{
    Task SendOtpAsync(string email, string otp);
}

public class EmailService : IEmailService
{
    private readonly ResendClient _resendClient;
    private readonly IConfiguration _configuration;
    private readonly ILogger<EmailService> _logger;

    public EmailService(ResendClient resendClient, IConfiguration configuration, ILogger<EmailService> logger)
    {
        _resendClient = resendClient;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task SendOtpAsync(string email, string otp)
    {
        var apiKey = _configuration["Resend:ApiKey"];
        var senderEmail = _configuration["Resend:SenderEmail"];
        var senderName = _configuration["Resend:SenderName"];

        // For development, just log the OTP
        if (string.IsNullOrEmpty(apiKey) || apiKey == "YOUR_RESEND_API_KEY")
        {
            _logger.LogWarning("DEVELOPMENT MODE: OTP for {Email} is {Otp}", email, otp);
            return;
        }

        try
        {
            var message = new EmailMessage
            {
                From = $"{senderName ?? "Fresh Farm Market"} <{senderEmail ?? "onboarding@resend.dev"}>",
                To = [email],
                Subject = "Your Fresh Farm Market Login OTP",
                HtmlBody =
                    $@"
                    <html>
                    <body>
                        <h2>Fresh Farm Market - Login Verification</h2>
                        <p>Your one-time password (OTP) is:</p>
                        <h1 style='color: #4CAF50; font-size: 32px; letter-spacing: 5px;'>{otp}</h1>
                        <p>This OTP is valid for 5 minutes.</p>
                        <p>If you did not request this, please ignore this email.</p>
                        <br/>
                        <p>Best regards,<br/>Fresh Farm Market Team</p>
                    </body>
                    </html>",
            };

            await _resendClient.EmailSendAsync(message);
            _logger.LogInformation("OTP email sent to {Email} via Resend", email);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send OTP email to {Email} via Resend", email);
            throw;
        }
    }
}
