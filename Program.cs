using System.Security.Cryptography;
using System.Net;
using DotNetEnv;

Env.Load();
Console.WriteLine("File Encryption Program");

Console.Write("Choose File Location / Action (F)etch or (P)ut or (L)ocal: ");
string r2Operation = Console.ReadLine()!.ToUpper();

try
{
    if (r2Operation == "L")
    {
        Console.Write("Enter file path: ");
        string filePath = Console.ReadLine()!;

        Console.Write("Choose operation (E)ncrypt or (D)ecrypt: ");
        string operation = Console.ReadLine()!.ToUpper();

        Console.Write("Enter Encryption / Decryption password: ");
        string password = Console.ReadLine()!;

        if (operation == "E")
        {
            EncryptFile(filePath, password);
            Console.WriteLine("File encrypted successfully.");
        }
        else if (operation == "D")
        {
            DecryptFile(filePath, password);
            Console.WriteLine("File decrypted successfully.");
        }
        else
        {
            Console.WriteLine("Invalid operation selected.");
        }
    }

    if (r2Operation == "F")
    {
        Console.Write("Enter Full File Name (ex. image.png): ");
        string r2filename = Console.ReadLine()!;
        await DownloadDataFromApi(Environment.GetEnvironmentVariable("R2API_URL")! + "/" + r2filename, r2filename);

        Console.Write("Choose operation (E)ncrypt or (D)ecrypt or (T)erminate: ");
        string operation = Console.ReadLine()!.ToUpper();

        if (operation == "E")
        {
            Console.Write("Enter Encryption / Decryption password: ");
            string password = Console.ReadLine()!;

            EncryptFile(r2filename, password);
            Console.WriteLine("File encrypted successfully.");
        }
        else if (operation == "D")
        {
            Console.Write("Enter Encryption / Decryption password: ");
            string password = Console.ReadLine()!;

            DecryptFile(r2filename, password);
            Console.WriteLine("File decrypted successfully.");
        }
        else if (operation == "T")
        {

        }
        else
        {
            Console.WriteLine("Invalid operation selected.");
        }
    }
    if (r2Operation == "P")
    {
        Console.Write("Enter Full File Name for R2 Storage(ex. image.png): ");
        string r2filename = Console.ReadLine()!;
        Console.Write("Enter local file path to upload: ");
        string localFilePath = Console.ReadLine()!;
        await UploadDataToApi(Environment.GetEnvironmentVariable("R2API_URL")! + "/" + r2filename, localFilePath);
    }
}
catch (Exception ex)
{
    Console.WriteLine($"An error occurred: {ex.Message}");
}

static async Task DownloadDataFromApi(string apiUrl, string outputPath)
{
    using var client = new HttpClient();
    client.DefaultRequestHeaders.Add("Authorization", "Bearer " + Environment.GetEnvironmentVariable("API_SECRET"));
    client.DefaultRequestHeaders.Add("User-Agent", "eApp/1.0");
    client.DefaultRequestHeaders.Add("Accept", "application/octet-stream");
    client.DefaultRequestHeaders.Add("Cache-Control", "no-cache");
    client.DefaultRequestHeaders.Add("Connection", "keep-alive");
    using var response = await client.GetAsync(apiUrl, HttpCompletionOption.ResponseHeadersRead);
    response.EnsureSuccessStatusCode();

    using var stream = await response.Content.ReadAsStreamAsync();
    using var fileStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None);

    byte[] buffer = new byte[8192];
    long totalBytesRead = 0;
    long? totalBytes = response.Content.Headers.ContentLength;

    // Progress Tracker
    while (true)
    {
        int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
        if (bytesRead == 0) break;

        await fileStream.WriteAsync(buffer, 0, bytesRead);

        totalBytesRead += bytesRead;

        if (totalBytes.HasValue)
        {
            double percentage = (double)totalBytesRead / totalBytes.Value * 100;
            Console.WriteLine($"Downloaded {percentage:F2}%");
        }
    }
}

static async Task UploadDataToApi(string apiUrl, string filePath)
{
    using var client = new HttpClient();
    client.DefaultRequestHeaders.Add("Authorization", "Bearer " + Environment.GetEnvironmentVariable("API_SECRET"));
    client.DefaultRequestHeaders.Add("User-Agent", "eApp/1.0");
    client.DefaultRequestHeaders.Add("Accept", "application/octet-stream");
    client.DefaultRequestHeaders.Add("Cache-Control", "no-cache");
    client.DefaultRequestHeaders.Add("Connection", "keep-alive");

    using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
    long totalBytes = fileStream.Length;
    long totalBytesRead = 0;

    var content = new ProgressStreamContent(fileStream, 8192, progress =>
    {
        totalBytesRead = progress;
        double percentage = (double)totalBytesRead / totalBytes * 100;
        Console.WriteLine($"Uploaded {percentage:F2}%");
    });
    content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");

    using var response = await client.PutAsync(apiUrl, content);
    response.EnsureSuccessStatusCode();

    Console.WriteLine("Upload completed successfully.");
}

void EncryptFile(string filePath, string password)
{
    byte[] salt = GenerateRandomBytes();
    byte[] key = DeriveKey(password, salt);

    string encryptedFilePath = filePath + ".encrypted";

    using Aes aes = Aes.Create();
    aes.Key = key;
    aes.IV = GenerateRandomBytes();

    using FileStream fsInput = new(filePath, FileMode.Open);
    using FileStream fsEncrypted = new(encryptedFilePath, FileMode.Create);
    fsEncrypted.Write(salt, 0, salt.Length);
    fsEncrypted.Write(aes.IV, 0, aes.IV.Length);

    using CryptoStream cs = new(fsEncrypted, aes.CreateEncryptor(), CryptoStreamMode.Write);
    fsInput.CopyTo(cs);
}

void DecryptFile(string filePath, string password)
{
    string decryptedFilePath = filePath.Replace(".encrypted", ".decrypted");

    using FileStream fsInput = new(filePath, FileMode.Open);
    byte[] salt = new byte[16];
    byte[] iv = new byte[16];
    fsInput.Read(salt, 0, salt.Length);
    fsInput.Read(iv, 0, iv.Length);

    byte[] key = DeriveKey(password, salt);

    using Aes aes = Aes.Create();
    aes.Key = key;
    aes.IV = iv;

    using FileStream fsDecrypted = new(decryptedFilePath, FileMode.Create);
    using CryptoStream cs = new(fsInput, aes.CreateDecryptor(), CryptoStreamMode.Read);
    cs.CopyTo(fsDecrypted);
}

byte[] GenerateRandomBytes()
{
    byte[] bytes = new byte[16];
    RandomNumberGenerator.Fill(bytes);
    return bytes;
}

byte[] DeriveKey(string password, byte[] salt)
{
    using var sha256 = SHA256.Create();
    byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
    byte[] passwordWithSalt = new byte[passwordBytes.Length + salt.Length];
    Buffer.BlockCopy(passwordBytes, 0, passwordWithSalt, 0, passwordBytes.Length);
    Buffer.BlockCopy(salt, 0, passwordWithSalt, passwordBytes.Length, salt.Length);

    return sha256.ComputeHash(passwordWithSalt);
}

public class ProgressStreamContent : StreamContent
{
    private readonly Stream _stream;
    private readonly int _bufferSize;
    private readonly Action<long> _progress;

    public ProgressStreamContent(Stream stream, int bufferSize, Action<long> progress) : base(stream, bufferSize)
    {
        _stream = stream;
        _bufferSize = bufferSize;
        _progress = progress;
    }

    protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
    {
        var buffer = new byte[_bufferSize];
        long totalBytesRead = 0;
        int bytesRead;
        while ((bytesRead = await _stream.ReadAsync(buffer, 0, buffer.Length)) != 0)
        {
            await stream.WriteAsync(buffer, 0, bytesRead);
            totalBytesRead += bytesRead;
            _progress(totalBytesRead);
        }
    }

    protected override bool TryComputeLength(out long length)
    {
        length = _stream.Length;
        return true;
    }
}
