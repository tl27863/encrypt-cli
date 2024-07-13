using System;
using System.IO;
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
    byte[] salt = GenerateRandomSalt();
    byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

    string encryptedFilePath = filePath + ".encrypted";

    using Aes aes = Aes.Create();
    Rfc2898DeriveBytes key = new(passwordBytes, salt, 50000);
    aes.Key = key.GetBytes(32);
    aes.IV = key.GetBytes(16);

    using FileStream fsInput = new(filePath, FileMode.Open);
    using FileStream fsEncrypted = new(encryptedFilePath, FileMode.Create);
    fsEncrypted.Write(salt, 0, salt.Length);

    using CryptoStream cs = new(fsEncrypted, aes.CreateEncryptor(), CryptoStreamMode.Write);
    fsInput.CopyTo(cs);
}

void DecryptFile(string filePath, string password)
{
    byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
    string decryptedFilePath = filePath.Replace(".encrypted", ".decrypted");

    using FileStream fsInput = new(filePath, FileMode.Open);
    byte[] salt = new byte[16];
    fsInput.Read(salt, 0, salt.Length);

    using Aes aes = Aes.Create();
    Rfc2898DeriveBytes key = new(passwordBytes, salt, 50000);
    aes.Key = key.GetBytes(32);
    aes.IV = key.GetBytes(16);

    using FileStream fsDecrypted = new(decryptedFilePath, FileMode.Create);
    using CryptoStream cs = new(fsInput, aes.CreateDecryptor(), CryptoStreamMode.Read);
    cs.CopyTo(fsDecrypted);
}

byte[] GenerateRandomSalt()
{
    byte[] salt = new byte[16];
    using (var rng = new RNGCryptoServiceProvider())
    {
        rng.GetBytes(salt);
    }
    return salt;
}
