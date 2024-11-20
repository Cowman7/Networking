using System.Net;
using System.Net.Sockets;

namespace Networking;

public class Server {
    public static void Main(string[] args) {
        Keyring ring = new();

        var ipEndPoint = new IPEndPoint(IPAddress.Any, 1855);
        Console.WriteLine(ipEndPoint);
        TcpListener listener = new(ipEndPoint);
    }
}
