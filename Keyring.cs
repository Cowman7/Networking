using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Networking;

public class Keyring {

    private Store store;

    /* Creates folder "Diplomacy" in the defualt "Documents" folder
     * Windows: C:\Users\{username}\Documents\Diplomacy
     * OSX: /Users/{username}/Diplomacy
     */
    public Keyring() {
        
        // OS nonspecific, Nab documents folder
        string directory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

        // OS specific, append folder name
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
            directory += "\\Diplomacy\\";
        }
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) {
            directory += "/Diplomacy/";
        }

        // OS nonspecific, create directory, does nothing if folder already exists
        Directory.CreateDirectory(directory);

        // Generates keystore, easier to keep in memory because recall is a more expensive task
        store = new(directory, "DiplomacyKeys", "Networking");
    }

    public void GenerateServerRSA() {
        if (store.FindKey("Server_RSA") == null) {
            store.AddKey("Server_RSA", RSA.Create().ExportRSAPrivateKey(), AlgoType.RSA);
        }
    }
}
