<#
.SYNOPSIS
    Renders src/Keylo.App/Assets/Logo.xaml to PNGs and a multi-size keylo.ico (PNG-compressed
    entries, Windows Vista+). Run after changing the logo.
#>
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName PresentationCore, PresentationFramework, WindowsBase

$root = Split-Path $PSScriptRoot -Parent
$dictionary = [System.Windows.Markup.XamlReader]::Parse((Get-Content (Join-Path $root 'src\Keylo.App\Assets\Logo.xaml') -Raw))
$logo = $dictionary['LogoImage']

function Render([int]$size) {
    $visual = New-Object System.Windows.Media.DrawingVisual
    $dc = $visual.RenderOpen()
    $dc.DrawImage($logo, (New-Object System.Windows.Rect 0, 0, $size, $size))
    $dc.Close()
    $bitmap = New-Object System.Windows.Media.Imaging.RenderTargetBitmap $size, $size, 96, 96, ([System.Windows.Media.PixelFormats]::Pbgra32)
    $bitmap.Render($visual)
    $encoder = New-Object System.Windows.Media.Imaging.PngBitmapEncoder
    $encoder.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
    $stream = New-Object System.IO.MemoryStream
    $encoder.Save($stream)
    return , $stream.ToArray()
}

$sizes = 16, 20, 24, 32, 40, 48, 64, 128, 256
$images = @{}
foreach ($s in $sizes) { $images[$s] = Render $s }

[System.IO.File]::WriteAllBytes((Join-Path $PSScriptRoot 'keylo-256.png'), $images[256])
[System.IO.File]::WriteAllBytes((Join-Path $PSScriptRoot 'keylo-1024.png'), (Render 1024))

# ICONDIR + ICONDIRENTRY[] + PNG payloads.
$ico = New-Object System.IO.MemoryStream
$w = New-Object System.IO.BinaryWriter $ico
$w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
foreach ($s in $sizes) {
    $dim = if ($s -ge 256) { 0 } else { $s }
    $w.Write([byte]$dim); $w.Write([byte]$dim); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([uint16]1); $w.Write([uint16]32)
    $w.Write([uint32]$images[$s].Length); $w.Write([uint32]$offset)
    $offset += $images[$s].Length
}
foreach ($s in $sizes) { $w.Write($images[$s]) }
$w.Flush()

$icoPath = Join-Path $root 'src\Keylo.App\Assets\keylo.ico'
[System.IO.File]::WriteAllBytes($icoPath, $ico.ToArray())
"Wrote $icoPath ($([math]::Round($ico.Length / 1KB)) KB, sizes $($sizes -join ', '))"
