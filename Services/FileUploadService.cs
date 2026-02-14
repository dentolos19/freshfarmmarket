namespace FreshFarmMarket.Services;

public interface IFileUploadService
{
    Task<(bool Success, string? FilePath, string? ErrorMessage)> UploadPhotoAsync(IFormFile file);
}

public class FileUploadService : IFileUploadService
{
    private readonly IWebHostEnvironment _environment;
    private readonly ILogger<FileUploadService> _logger;
    private const string UploadFolder = "uploads";
    private const long MaxFileSize = 5 * 1024 * 1024; // 5MB

    public FileUploadService(IWebHostEnvironment environment, ILogger<FileUploadService> logger)
    {
        _environment = environment;
        _logger = logger;
    }

    public async Task<(bool Success, string? FilePath, string? ErrorMessage)> UploadPhotoAsync(IFormFile file)
    {
        if (file == null || file.Length == 0)
        {
            return (false, null, "No file uploaded");
        }

        if (file.Length > MaxFileSize)
        {
            return (false, null, "File size exceeds 5MB limit");
        }

        // Validate file extension (only .jpg allowed)
        var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
        if (extension != ".jpg" && extension != ".jpeg")
        {
            return (false, null, "Only .JPG files are allowed");
        }

        // Validate MIME type
        if (file.ContentType.ToLowerInvariant() != "image/jpeg")
        {
            return (false, null, "Invalid file type. Only JPEG images are allowed");
        }

        // Additional validation: Check file signature (magic bytes)
        if (!await IsValidJpegAsync(file))
        {
            return (false, null, "File content does not match JPEG format");
        }

        try
        {
            var uploadPath = Path.Combine(_environment.WebRootPath, UploadFolder);

            // Ensure directory exists
            if (!Directory.Exists(uploadPath))
            {
                Directory.CreateDirectory(uploadPath);
            }

            // Generate unique filename
            var fileName = $"{Guid.NewGuid()}.jpg";
            var filePath = Path.Combine(uploadPath, fileName);

            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await file.CopyToAsync(stream);
            }

            var relativePath = $"/{UploadFolder}/{fileName}";
            _logger.LogInformation("File uploaded successfully: {FilePath}", relativePath);

            return (true, relativePath, null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error uploading file");
            return (false, null, "An error occurred while uploading the file");
        }
    }

    private static async Task<bool> IsValidJpegAsync(IFormFile file)
    {
        // JPEG magic bytes: FF D8 FF
        var jpegSignature = new byte[] { 0xFF, 0xD8, 0xFF };

        using var stream = file.OpenReadStream();
        var headerBytes = new byte[3];
        var bytesRead = await stream.ReadAsync(headerBytes.AsMemory(0, 3));

        if (bytesRead < 3)
        {
            return false;
        }

        return headerBytes[0] == jpegSignature[0]
               && headerBytes[1] == jpegSignature[1]
               && headerBytes[2] == jpegSignature[2];
    }
}
