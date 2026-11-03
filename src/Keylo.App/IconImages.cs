using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Keylo.Core;

namespace Keylo.App;

/// <summary>
/// Uploaded icon images. Each is resampled to fit a square canvas (aspect ratio kept, centred on
/// transparency, nothing cropped) and stored as icons\{hash}.png. A secret or category refers to one
/// by the icon name "img" + hash, which stays a plain alphanumeric icon name in Credential Manager.
/// </summary>
public static class IconImages
{
    public const int CanvasSize = 128;
    private const string Prefix = "img";
    private static readonly string Directory = KeyloPaths.IconDirectory;
    private static readonly Dictionary<string, ImageSource?> Cache = new(StringComparer.OrdinalIgnoreCase);

    public static bool IsImage(string? icon) => icon is { Length: 35 } && icon.StartsWith(Prefix, StringComparison.Ordinal);

    /// <summary>Resamples and stores <paramref name="sourcePath"/>; returns the icon name to save on the secret or category.</summary>
    public static string Import(string sourcePath)
    {
        BitmapSource source;
        try
        {
            var decoder = BitmapDecoder.Create(new Uri(sourcePath), BitmapCreateOptions.IgnoreColorProfile, BitmapCacheOption.OnLoad);
            source = decoder.Frames[0];
        }
        catch (Exception ex) when (ex is NotSupportedException or FileFormatException or IOException)
        {
            throw new KeyloException($"'{Path.GetFileName(sourcePath)}' isn't an image Keylo can read.");
        }

        var png = Encode(FitToCanvas(source));
        var hash = Convert.ToHexString(SHA256.HashData(png))[..32].ToLowerInvariant();

        System.IO.Directory.CreateDirectory(Directory);
        var path = Path.Combine(Directory, hash + ".png");
        if (!File.Exists(path)) File.WriteAllBytes(path, png);
        return Prefix + hash;
    }

    /// <summary>The stored image for an "img…" icon name, or null (not an image, or the file is gone).</summary>
    public static ImageSource? Load(string? icon)
    {
        if (!IsImage(icon)) return null;
        if (Cache.TryGetValue(icon!, out var cached)) return cached;

        var path = Path.Combine(Directory, icon![Prefix.Length..] + ".png");
        ImageSource? image = null;
        if (File.Exists(path))
        {
            var bitmap = new BitmapImage();
            bitmap.BeginInit();
            bitmap.CacheOption = BitmapCacheOption.OnLoad; // don't hold the file open
            bitmap.UriSource = new Uri(path);
            bitmap.EndInit();
            bitmap.Freeze();
            image = bitmap;
        }

        Cache[icon] = image;
        return image;
    }

    /// <summary>Uniform scale to fit CanvasSize×CanvasSize (never upscaled past 2×), centred on transparency.</summary>
    private static BitmapSource FitToCanvas(BitmapSource source)
    {
        double width = source.PixelWidth, height = source.PixelHeight;
        var scale = Math.Min(Math.Min(CanvasSize / width, CanvasSize / height), 2.0);
        var drawWidth = width * scale;
        var drawHeight = height * scale;

        var visual = new DrawingVisual();
        RenderOptions.SetBitmapScalingMode(visual, BitmapScalingMode.Fant);
        using (var dc = visual.RenderOpen())
        {
            dc.DrawImage(source, new Rect((CanvasSize - drawWidth) / 2, (CanvasSize - drawHeight) / 2, drawWidth, drawHeight));
        }

        var target = new RenderTargetBitmap(CanvasSize, CanvasSize, 96, 96, PixelFormats.Pbgra32);
        target.Render(visual);
        target.Freeze();
        return target;
    }

    private static byte[] Encode(BitmapSource bitmap)
    {
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var stream = new MemoryStream();
        encoder.Save(stream);
        return stream.ToArray();
    }
}
