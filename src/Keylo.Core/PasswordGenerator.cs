using System.Security.Cryptography;

namespace Keylo.Core;

public static class PasswordGenerator
{
    private const string Lower = "abcdefghijkmnopqrstuvwxyz";
    private const string Upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private const string Digits = "23456789";
    private const string Symbols = "!@#$%^&*-_=+?";

    /// <summary>
    /// A random password with at least one character from each enabled set. Look-alike characters
    /// (l, I, O, 0, 1) are left out so values survive being read aloud or retyped.
    /// </summary>
    public static string Generate(int length = 24, bool symbols = true)
    {
        length = Math.Clamp(length, 8, 128);
        string[] sets = symbols ? [Lower, Upper, Digits, Symbols] : [Lower, Upper, Digits];
        var all = string.Concat(sets);

        var chars = new char[length];
        for (var i = 0; i < sets.Length; i++) chars[i] = Pick(sets[i]);
        for (var i = sets.Length; i < length; i++) chars[i] = Pick(all);

        RandomNumberGenerator.Shuffle(chars.AsSpan());
        return new string(chars);
    }

    private static char Pick(string set) => set[RandomNumberGenerator.GetInt32(set.Length)];
}
