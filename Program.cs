using System.Security.Cryptography;

Console.WriteLine("File Encryption Program");
Console.Write("Enter file path: ");
string filePath = Console.ReadLine()!;

Console.Write("Enter password: ");
string password = Console.ReadLine()!;

Console.Write("Choose operation (E)ncrypt or (D)ecrypt: ");
string operation = Console.ReadLine()!.ToUpper();

try
{
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
catch (Exception ex)
{
    Console.WriteLine($"An error occurred: {ex.Message}");
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
