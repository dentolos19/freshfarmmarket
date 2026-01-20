using System.Text.Json;

namespace FreshFarmMarket.Services;

public interface IRecaptchaService
{
    Task<bool> ValidateAsync(string token);
}

public class RecaptchaService : IRecaptchaService
{
    private readonly IConfiguration _configuration;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<RecaptchaService> _logger;
    private const double MinimumScore = 0.5;

    public RecaptchaService(
        IConfiguration configuration,
        IHttpClientFactory httpClientFactory,
        ILogger<RecaptchaService> logger
    )
    {
        _configuration = configuration;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public async Task<bool> ValidateAsync(string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            _logger.LogWarning("reCAPTCHA token is empty");
            return false;
        }

        var secretKey = _configuration["ReCaptcha:SecretKey"];

        // For development, skip validation if secret key is placeholder
        if (string.IsNullOrEmpty(secretKey) || secretKey == "YOUR_RECAPTCHA_SECRET_KEY")
        {
            _logger.LogWarning("DEVELOPMENT MODE: Skipping reCAPTCHA validation");
            return true;
        }

        try
        {
            var client = _httpClientFactory.CreateClient();
            var response = await client.PostAsync(
                $"https://www.google.com/recaptcha/api/siteverify?secret={secretKey}&response={token}",
                null
            );

            var jsonResponse = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<RecaptchaResponse>(jsonResponse);

            if (result == null)
            {
                _logger.LogWarning("reCAPTCHA response deserialization failed");
                return false;
            }

            if (!result.Success)
            {
                _logger.LogWarning(
                    "reCAPTCHA validation failed: {ErrorCodes}",
                    string.Join(", ", result.ErrorCodes ?? Array.Empty<string>())
                );
                return false;
            }

            if (result.Score < MinimumScore)
            {
                _logger.LogWarning("reCAPTCHA score too low: {Score}", result.Score);
                return false;
            }

            _logger.LogInformation("reCAPTCHA validated successfully with score: {Score}", result.Score);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "reCAPTCHA validation error");
            return false;
        }
    }

    private class RecaptchaResponse
    {
        [System.Text.Json.Serialization.JsonPropertyName("success")]
        public bool Success { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("score")]
        public double Score { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("action")]
        public string? Action { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("challenge_ts")]
        public string? ChallengeTs { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("hostname")]
        public string? Hostname { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("error-codes")]
        public string[]? ErrorCodes { get; set; }
    }
}
