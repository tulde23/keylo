using System.Security.Cryptography;
using Avalonia;
using Avalonia.Media.Imaging;
using Keylo.Core;

namespace Keylo.Desktop;

/// <summary>
/// Uploaded icon images, stored as the Windows app does: resampled to fit a 128×128 canvas (aspect
/// kept, centred on transparency, nothing cropped) and saved as icons/{hash}.png, named "img" + hash.
/// </summary>
public static class IconImages
{
    private const int CanvasSize = 128;

    public static string Import(string sourcePath)
    {
        Bitmap source;
        try
        {
            source = new Bitmap(sourcePath);
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or InvalidOperationException or NotSupportedException)
        {
            throw new KeyloException($"'{Path.GetFileName(sourcePath)}' isn't an image Keylo can read.");
        }

        byte[] png;
        using (source)
        {
            double width = source.PixelSize.Width, height = source.PixelSize.Height;
            var scale = Math.Min(Math.Min(CanvasSize / width, CanvasSize / height), 2.0);
            var draw = new Size(width * scale, height * scale);

            using var canvas = new RenderTargetBitmap(new PixelSize(CanvasSize, CanvasSize));
            using (var context = canvas.CreateDrawingContext())
            {
                context.DrawImage(source, new Rect(source.Size),
                    new Rect(new Point((CanvasSize - draw.Width) / 2, (CanvasSize - draw.Height) / 2), draw));
            }
            using var stream = new MemoryStream();
            canvas.Save(stream);
            png = stream.ToArray();
        }

        var hash = System.Convert.ToHexString(SHA256.HashData(png))[..32].ToLowerInvariant();
        Directory.CreateDirectory(KeyloPaths.IconDirectory);
        var path = Path.Combine(KeyloPaths.IconDirectory, hash + ".png");
        if (!File.Exists(path)) File.WriteAllBytes(path, png);
        return "img" + hash;
    }
}
