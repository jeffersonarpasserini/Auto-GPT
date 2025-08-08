using System.Security.Cryptography;
using System.Text;
using UserAuthApi.Models;

namespace UserAuthApi.Services;

public class UserService
{
    private readonly List<User> _users = new();

    public bool Register(string username, string password)
    {
        if (_users.Any(u => u.Username == username))
        {
            return false;
        }

        CreatePasswordHash(password, out var hash, out var salt);
        _users.Add(new User { Username = username, PasswordHash = hash, PasswordSalt = salt });
        return true;
    }

    public User? Authenticate(string username, string password)
    {
        var user = _users.SingleOrDefault(u => u.Username == username);
        if (user is null)
        {
            return null;
        }

        return VerifyPasswordHash(password, user.PasswordHash, user.PasswordSalt) ? user : null;
    }

    private static void CreatePasswordHash(string password, out byte[] hash, out byte[] salt)
    {
        using var hmac = new HMACSHA512();
        salt = hmac.Key;
        hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
    }

    private static bool VerifyPasswordHash(string password, byte[] hash, byte[] salt)
    {
        using var hmac = new HMACSHA512(salt);
        var computed = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
        return computed.SequenceEqual(hash);
    }
}
