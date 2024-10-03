# Encrypt CLI

This C# CLI provides functionality for encrypting and decrypting files locally and interacting with Cloudflare R2 Storage Bucket.

## Features

- Local file encryption and decryption
- Download files from R2 storage
- Upload files to R2 storage
- Encrypt and decrypt downloaded files
- Progress tracking for file uploads and downloads

## Prerequisites

- .NET Core SDK (version compatible with the program)
- DotNetEnv package for environment variable management
- Active R2 storage account and API access

## Setup

1. Clone the repository or download the source code.
2. Create Worker based on R2 Example with API Secret for authentication.
3. Create a `.env` file in the project root with the following variables:
   ```
   R2API_URL=your_r2_api_url
   API_SECRET=your_api_secret
   ```
4. Install required packages:
   ```
   dotnet add package DotNetEnv
   ```

## Usage

Run the program using:
```
dotnet run
```

Follow the on-screen prompts to:
1. Choose operation mode: (F)etch, (P)ut, or (L)ocal
2. Provide file paths or names as requested
3. Select encryption or decryption operations
4. Enter encryption/decryption passwords when prompted

### Operation Modes

- **Fetch (F)**: Download a file from R2 storage
- **Put (P)**: Upload a local file to R2 storage
- **Local (L)**: Perform encryption/decryption on local files
