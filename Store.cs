using System.Security.Cryptography;
using System.Text;

namespace Networking;

public class Store {
    public readonly string Path;
    public readonly string Name;

    private readonly byte[] PasswordKey;
    private readonly byte[] IV;

    private int entries = 0;
    private Dictionary<string, (AlgoType, byte[]?)> keys = new();

    public Store(string Directory, string Store_Name, string Password) {
        Name = Store_Name;
        Path = Directory + Store_Name + ".csks";
        PasswordKey = GenerateKey(Password);
        IV = GenerateIV(Password);
        InitializeStore();
    }

    private void InitializeStore() {
        if (File.Exists(Path)) {
            string filedata = DecryptFile();
            var lines = filedata.Split("\n");
            
            entries = int.Parse(lines[0]);

            if (entries == 0) { return; }

            string[] index = new string[entries];
            for (int i = 0; i < entries; i++) {
                string name = lines[i + 1];

                var data = lines[i + entries + 1].Split(",");
                var stored = Convert.FromBase64String(data[1]);
                keys.Add(name, ((AlgoType)int.Parse(data[0]), stored));
            }
            return;
        }

        string contents = "0\n";

        byte[] output = EncryptFile(contents);

        using (var fs = File.Create(Path)) {
            foreach(byte b in output) {
                fs.WriteByte(b);
            }
        }
    }

    public void AddKey(string Name, byte[] PrivateKey, AlgoType Type) {
        if (Type != AlgoType.RSA) { Console.WriteLine("ERROR: This method only allows for RSA storage."); return; }
        
        if (FindKey(Name) != null) {
            Console.WriteLine("Key " + Name + " has already been added");
            return;
        }

        entries++;
        keys.Add(Name, (Type, PrivateKey));

        Compile();
    }

    public void AddKey(string Name, SymmetricAlgorithm Algo, AlgoType Type) {
        if (Type == AlgoType.RSA) { Console.WriteLine("ERROR: This method does not allow Asymetric Algorithms, only AES, and TripleDES."); return; }
        if (FindKey(Name) != null) {
            Console.WriteLine("Key " + Name + " has already been added");
            return;
        }

        byte[] key = Algo.Key;
        byte[] iv = Algo.IV;

        byte[] stored_value = new byte[key.Length + iv.Length + 1];

        for (int i = 0; i < stored_value.Length; i++) {
            if (i < key.Length) {
                stored_value[i] = key[i];
            } else if (i == key.Length) {
                stored_value[i] = 44;
            } else {
                stored_value[i] = iv[i - key.Length - 1];
            }
        }

        entries++;
        keys.Add(Name, (Type, stored_value));
        
        Compile();
    }


    public void GetKey(string Name, out object? Output) {
        var key = FindKey(Name);
        if (key == null) {
            Console.WriteLine("Key " + Name + " does not exist");
            Output = null;
            return;
        }
        
        switch (key.Value.Item1) {
            case AlgoType.AES: {
                SymmetricAlgorithm Algo = Aes.Create();
                Output = DecompressKey(key.Value.Item2, Algo);
            } break;
            case AlgoType.RSA: {
                var Algo = RSA.Create();
                Output = DecompressKey(key.Value.Item2, Algo);
            } break;
            case AlgoType.TripleDES: {
                SymmetricAlgorithm Algo = TripleDES.Create();
                Output = DecompressKey(key.Value.Item2, Algo);
            } break;
            default:
                Output = null;
            break;
        }
    }

    private static SymmetricAlgorithm? DecompressKey(byte[]? keydata, SymmetricAlgorithm Algo) {
        if (keydata == null) {
            Console.Write("Keydata is empty");
            return null;
        }
        var key_values = Encoding.ASCII.GetString(keydata).Split(",");
        Algo.Key = Encoding.ASCII.GetBytes(key_values[0]);
        Algo.IV = Encoding.ASCII.GetBytes(key_values[1]);
        return Algo;
    }

    private static RSA? DecompressKey(byte[]? keydata, RSA Algo) {
        if (keydata == null) {
            Console.Write("Keydata is empty");
            return null;
        }
        ReadOnlySpan<byte> bytes = keydata;
        Algo.ImportRSAPrivateKey(bytes, out int bytesread);
        return Algo;
    }

    public void RemoveKey(string Name) {
        
        Compile();
    }

    public (AlgoType, byte[]?)? FindKey(string Name) {
        keys.TryGetValue(Name, out var keydata);
        
        return keydata.Equals((AlgoType.AES, null)) ? null : keydata;
    }

    private void Compile() {
        string contents = entries.ToString() + "\n";

        foreach (var entry in keys) {
            contents += entry.Key + "\n";
        }
        foreach (var entry in keys) {
            contents += entry.Value.Item1.GetHashCode().ToString() + "," + Convert.ToBase64String(entry.Value.Item2) + "\n";
        }

        byte[] output = EncryptFile(contents);

        using (var fs = File.Create(Path)) {
            foreach(byte b in output) {
                fs.WriteByte(b);
            }
        }
    }

    private byte[] EncryptFile(string FileContents) {
        var algo = Aes.Create();
        algo.Key = PasswordKey;
        algo.IV = IV;

        var encryptor = algo.CreateEncryptor(algo.Key, algo.IV);
        using (var msEncrypt = new MemoryStream()) {
            using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write)) {
                using (var swEncrypt = new StreamWriter(csEncrypt)) {
                    swEncrypt.Write(FileContents);
                }
            }
            return msEncrypt.ToArray();
        }
    }

    private string DecryptFile() {
        using (var fs = File.OpenRead(Path)) {
            var algo = Aes.Create();
            algo.Key = PasswordKey;
            algo.IV = IV;

            var decryptor = algo.CreateDecryptor(algo.Key, algo.IV);

            using (var csDecrypt = new CryptoStream(fs, decryptor, CryptoStreamMode.Read)) {
                using (var srDecrypt = new StreamReader(csDecrypt)) {
                    return srDecrypt.ReadToEnd();
                }
            }
        }
    }

    private static byte[] GenerateKey(string Password) {
        byte[] key = SHA256.HashData(Encoding.ASCII.GetBytes(Password));
        return key;
    }

    private static byte[] GenerateIV(string Password) {
        byte[] IV = new byte[16];

        // Spans password over 16 bytes by repeating from beginning if password is less than 16 characters
        // i.e. Password: 'Jelly'   IV: 'JellyJellyJellyJ'
        var pArr = Encoding.ASCII.GetBytes(Password);
        for (int bi = 0, pi = 0; bi < 16; bi++, pi++) {
            if (pi >= Password.Length) { pi = 0; }
            IV[bi] = pArr[pi];
        }

        return IV;
    }
}
