# HTB Reversing Challenge: Bypass

https://app.hackthebox.com/challenges/Bypass

## 🧩 Challenge Info

- **Challenge Name:** Bypass  
- **Description:** The Client is in full control. Bypass the authentication and read the key to get the Flag.  
- **Filename:** `Bypass.zip`  
- **SHA-256 (zip):** `97bf53884e0d9880ac4d75c4281622f7e0a4e6bafe7378b9940cf888309821ab`  
- **Extracted File:** `Bypass.exe`  
- **Difficulty:** Easy  
- **File Type:** Portable Executable 32-bit (.NET Assembly)  
- **Tools Used:** CFF Explorer, dnSpy, Hex Editor (HxD)

## 🕵️ Initial Analysis (CFF Explorer)

Using **CFF Explorer**, I confirmed the binary is a .NET executable with the following details:

- **SHA1:** `4860E8485746C1D63A6A40E32BF03ECFDA3007D4`
- **File Info:** Microsoft Visual Studio .NET
- **File Description/Internal Name:** `HTBChallange.exe`

Since it's an easy .NET challenge, I skipped traditional PE header inspection and moved directly to the **.NET Directory** (see image above).

No visible flags or credentials in the Strings section. However, some interesting references were found, including:

- `CreateDecryptor`
- `CryptoStream`

These hinted at encrypted resources and obfuscation techniques.

## 🚀 Runtime Behavior

Running `Bypass.exe` directly (no debugger) resulted in a simple console app:

```
Username: hola 
Password: hola
Wrong Username and/or Password
```

This means credentials are required, likely validated internally.

## 🔎 Deep Dive with dnSpy

I used **dnSpy (32-bit)** from [https://github.com/dnSpy/dnSpy/releases](https://github.com/dnSpy/dnSpy/releases) to reverse the IL code.

In the **Resources** section, there was one entry: `0`  
In the **Assembly Explorer**, I found 8 classes named numerically from `0` to `7`.

The entry point (class `<Module>`) simply invokes:

```csharp
static <Module>() {
    5.0();
}
```

So I inspected class 5, method 0():

```csharp
internal static class 5 {
    public static void 0() {
        6 <<EMPTY_NAME>> = new 6(global::7.3(Assembly.GetExecutingAssembly().GetManifestResourceStream("0")));
        global::5.0 = <<EMPTY_NAME>>.6();
        global::5.1 = <<EMPTY_NAME>>.6();
        
        etc..
    }
}
```

The resource 0 is passed to 7.3() → 7.2() → which performs AES CBC mode decryption.

🔐 Decryption Routine in Class 7

Here’s the decryption logic in method 7.2():

```csharp
public static byte[] 2(byte[] input) {
    using (RijndaelManaged rijndael = new RijndaelManaged()) {
        rijndael.BlockSize = 128;
        rijndael.Mode = CipherMode.CBC;
        rijndael.GenerateKey();
        rijndael.GenerateIV();

        using (MemoryStream ms = new MemoryStream(input)) {
            byte[] key = new byte[rijndael.Key.Length];
            byte[] iv = new byte[rijndael.IV.Length];
            ms.Read(key, 0, key.Length);
            ms.Read(iv, 0, iv.Length);
            using (ICryptoTransform decryptor = rijndael.CreateDecryptor(key, iv))
            using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read)) {
                byte[] result = new byte[ms.Length - ms.Position];
                cs.Read(result, 0, result.Length);
                return result;
            }
        }
    }
}

```

Confirmed: AES CBC 128 decryption using key/IV from the start of the stream. This explains the Crypto references found earlier.
🧪 Extracting the Flag

I exported the resource named 0 from the Resources tree as blob.enc.

Opened it in a Hex Editor — clearly an obfuscated/encrypted blob.

```
7C 05 FF 52 46 7E B1 78 E4 F5 28 3A F4 CC F8 53 92 5A 54 C6 19 F5 51 D5 53 46 36 EC A6 3D 97 01 5D 6D 00 20 03 26 22 A1 32 8D 43 0F 7F 68 7B 15 01 0D 1D EA 46 63 9D C5 42 A3 50 E5 B3 C4 2F 9B A9 DF EA 76 E3 0A 34 45 3D BC 21 5D E7 10 66 FF 74 60 23 30 3B A3 FA B7 1B 3B 65 F9 49 39 6F 3A....
```

Set a breakpoint at the return result; of the AES decryptor function in dnSpy, then ran the program.

After hitting the breakpoint:

    Right-clicked the result variable → Memory View.

    Dumped the decrypted contents.

🏁 Inside the Dump

The decrypted memory contained all hardcoded strings used by the app, including:

    The correct Username

    The correct Password

    The HTB Flag

(Note: Strings were UTF-16 encoded, so they appeared with 00 bytes between characters.)

✅ Conclusion

This challenge was a classic .NET reversing problem focused on embedded encrypted resources and runtime decryption. Once decrypted, the sensitive strings were easily retrievable through memory inspection at runtime.

Skills practiced:

    .NET reversing with dnSpy

    AES/CryptoStream analysis

    Runtime breakpoint debugging

    Memory inspection and hex analysis

Tools Used:

    CFF Explorer

    dnSpy (32-bit)

    Hex Editor (any of your choice - I use HxD)

