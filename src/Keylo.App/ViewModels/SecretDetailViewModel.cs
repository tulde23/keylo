using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Keylo.App.Services;
using Keylo.Core;
using Microsoft.Win32;

namespace Keylo.App.ViewModels;

public sealed record ProviderItem(string Id, string DisplayName)
{
    public string PushLabel => $"Push to {DisplayName}";
}

/// <summary>The right-hand panel: viewing, editing or creating one secret.</summary>
public sealed partial class SecretDetailViewModel : ObservableObject
{
    private readonly KeyloService _keylo;
    private readonly IUserNotifier _notify;
    private readonly Func<string?, Task> _reload;
    private readonly DispatcherTimer _hideTimer = new() { Interval = TimeSpan.FromSeconds(30) };

    private SecretInfo? _info;
    private byte[]? _binaryValue;

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(IsViewing), nameof(Title))]
    private bool _isEditing;

    [ObservableProperty] private string _name = "";
    [ObservableProperty] private string _category = "";
    [ObservableProperty] private string _username = "";
    [ObservableProperty] private string _notes = "";
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(Symbol), nameof(Image), nameof(HasImage), nameof(TileBrush))] private string? _icon;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(TileBrush))] private string? _color;

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(ValueLength))]
    private string _value = "";

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(MaskedValue))]
    private bool _isValueVisible;

    [ObservableProperty] private bool _isBinary;
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private int _generatorLength = 24;
    [ObservableProperty] private bool _generatorSymbols = true;

    public SecretDetailViewModel(KeyloService keylo, IUserNotifier notify, Func<string?, Task> reload, SecretInfo? info)
    {
        _keylo = keylo;
        _notify = notify;
        _reload = reload;
        _hideTimer.Tick += (_, _) => HideValue();

        Categories = new ObservableCollection<string>(keylo.Store.Categories());
        Providers = new ObservableCollection<ProviderItem>(keylo.Providers.All.Select(p => new ProviderItem(p.Id, p.DisplayName)));

        if (info is null)
        {
            IsNew = true;
            IsEditing = true;
            IsValueVisible = true;
        }
        else
        {
            Load(info);
        }
    }

    public bool IsNew { get; }
    public bool IsViewing => !IsEditing;
    public string Title => IsNew ? "New secret" : Name;
    public ObservableCollection<string> Categories { get; }
    public ObservableCollection<ProviderItem> Providers { get; }

    public string MaskedValue => IsValueVisible ? Value : "••••••••••••••••";

    /// <summary>Header tile: own icon/colour, falling back to the category's, then Keylo's default.</summary>
    public Wpf.Ui.Controls.SymbolRegular Symbol =>
        IconCatalog.ToSymbol(Icon ?? _keylo.Categories.StyleOf(Category)?.Icon, Wpf.Ui.Controls.SymbolRegular.Key24);

    public System.Windows.Media.ImageSource? Image => IconImages.Load(Icon ?? _keylo.Categories.StyleOf(Category)?.Icon);

    public bool HasImage => Image is not null;

    public System.Windows.Media.Brush TileBrush => HasImage ? System.Windows.Media.Brushes.Transparent :
        IconCatalog.Tile(IconCatalog.ToColor(Color) ?? IconCatalog.ToColor(_keylo.Categories.StyleOf(Category)?.Color) ?? IconCatalog.ToColor("#6366F1")!.Value);
    public int ValueLength => Value.Length;

    public string UpdatedText => _info is null ? "" : _info.UpdatedAt.LocalDateTime.ToString("MMM d, yyyy  h:mm tt");
    public string SizeText => _info switch
    {
        null => "",
        { Size: 1 } => "1 byte",
        { Size: < 1024 } => $"{_info.Size} bytes",
        _ => $"{_info.Size / 1024.0:0.#} KB",
    };
    public string StorageText => _info?.Storage == StorageKind.EncryptedFile ? "Encrypted file (DPAPI)" : "Windows Credential Manager";
    public bool HasUsername => !string.IsNullOrEmpty(_info?.Username);
    public bool HasNotes => !string.IsNullOrEmpty(_info?.Notes);
    public bool HasCategory => !string.IsNullOrEmpty(_info?.Category);

    // The header tile falls back to the category's style, so it follows category edits.
    partial void OnCategoryChanged(string value)
    {
        OnPropertyChanged(nameof(Symbol));
        OnPropertyChanged(nameof(Image));
        OnPropertyChanged(nameof(HasImage));
        OnPropertyChanged(nameof(TileBrush));
    }

    private void Load(SecretInfo info)
    {
        _info = info;
        Name = info.Name;
        Category = info.Category ?? "";
        Username = info.Username ?? "";
        Notes = info.Notes ?? "";
        Icon = info.Icon;
        Color = info.Color;
        Value = "";
        IsValueVisible = false;
        IsBinary = false;
        OnPropertyChanged(nameof(UpdatedText));
        OnPropertyChanged(nameof(SizeText));
        OnPropertyChanged(nameof(StorageText));
        OnPropertyChanged(nameof(HasUsername));
        OnPropertyChanged(nameof(HasNotes));
        OnPropertyChanged(nameof(HasCategory));
        OnPropertyChanged(nameof(Title));
    }

    /// <summary>Reads the value after an access check. Returns false when it couldn't be read.</summary>
    private async Task<bool> LoadValueAsync(string why)
    {
        if (_info is null) return true;
        try
        {
            await _keylo.EnsureValueAccessAsync($"{why} '{_info.Name}'");
            var bytes = _keylo.Store.Get(_info.Name).Value;
            var text = KeyloService.DecodeText(bytes);
            IsBinary = text is null;
            _binaryValue = text is null ? bytes : null;
            Value = text ?? $"Binary value ({bytes.Length} bytes) — use Export or Replace from file";
            return true;
        }
        catch (KeyloException ex)
        {
            _notify.Error(ex.Message);
            return false;
        }
    }

    [RelayCommand]
    private async Task ToggleValue()
    {
        if (IsValueVisible)
        {
            HideValue();
            return;
        }

        if (!await LoadValueAsync("show")) return;
        IsValueVisible = true;
        _hideTimer.Stop();
        _hideTimer.Start();
    }

    private void HideValue()
    {
        _hideTimer.Stop();
        IsValueVisible = false;
        if (!IsEditing) Value = "";
    }

    [RelayCommand]
    private async Task CopyValue()
    {
        if (_info is null) return;
        var visible = IsValueVisible;
        if (!await LoadValueAsync("copy")) return;
        if (IsBinary)
        {
            _notify.Error("Binary values can't be copied. Use Export instead.");
            return;
        }

        _keylo.CopyToClipboard(Value);
        if (!visible) Value = "";
        _notify.Success($"Copied. Clears from the clipboard in {_keylo.Config.ClipboardSeconds}s.");
    }

    [RelayCommand]
    private void CopyUsername()
    {
        if (string.IsNullOrEmpty(_info?.Username)) return;
        _keylo.CopyToClipboard(_info.Username);
        _notify.Success("Key copied.");
    }

    [RelayCommand]
    private async Task Edit()
    {
        if (!await LoadValueAsync("edit")) return;
        IsValueVisible = !IsBinary;
        IsEditing = true;
        _hideTimer.Stop();
    }

    [RelayCommand]
    private async Task Cancel()
    {
        if (IsNew)
        {
            await _reload(null);
            return;
        }

        IsEditing = false;
        if (_info is not null) Load(_info);
    }

    [RelayCommand]
    private void Generate()
    {
        Value = PasswordGenerator.Generate(GeneratorLength, GeneratorSymbols);
        IsValueVisible = true;
        IsBinary = false;
        _binaryValue = null;
    }

    [RelayCommand]
    private void ReplaceFromFile()
    {
        var dialog = new OpenFileDialog { Title = "Replace value from file" };
        if (dialog.ShowDialog() != true) return;

        var bytes = File.ReadAllBytes(dialog.FileName);
        var text = KeyloService.DecodeText(bytes);
        IsBinary = text is null;
        _binaryValue = text is null ? bytes : null;
        Value = text ?? $"Binary value ({bytes.Length} bytes) from {Path.GetFileName(dialog.FileName)}";
        IsValueVisible = text is not null;
    }

    [RelayCommand]
    private async Task Export()
    {
        if (_info is null) return;
        var dialog = new SaveFileDialog { Title = "Export value", FileName = _info.Name };
        if (dialog.ShowDialog() != true) return;

        try
        {
            await _keylo.EnsureValueAccessAsync($"export '{_info.Name}'");
            await File.WriteAllBytesAsync(dialog.FileName, _keylo.Store.Get(_info.Name).Value);
            _notify.Success($"Exported to {dialog.FileName}. That file is not encrypted.");
        }
        catch (Exception ex) when (ex is KeyloException or IOException or UnauthorizedAccessException)
        {
            _notify.Error(ex.Message);
        }
    }

    [RelayCommand]
    private async Task Save()
    {
        var value = IsBinary && _binaryValue is not null ? _binaryValue : Encoding.UTF8.GetBytes(Value);
        if (value.Length == 0)
        {
            _notify.Error("Enter a value.");
            return;
        }

        IsBusy = true;
        try
        {
            await _keylo.EnsureBrowseAsync();
            var saved = _keylo.Store.Save(
                new SecretDraft(Name, value, Category, Username, Notes, Icon, Color),
                originalName: IsNew ? null : _info?.Name);

            _notify.Success(IsNew ? $"Added '{saved.Name}'." : $"Saved '{saved.Name}'.");
            Value = "";
            await _reload(saved.Name);
        }
        catch (KeyloException ex)
        {
            _notify.Error(ex.Message);
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task Delete()
    {
        if (_info is null) return;
        if (!await _notify.ConfirmAsync("Delete secret", $"Delete '{_info.Name}'? This can't be undone.", "Delete")) return;

        try
        {
            await _keylo.EnsureBrowseAsync();
            _keylo.Store.Delete(_info.Name);
            _notify.Success($"Deleted '{_info.Name}'.");
            await _reload(null);
        }
        catch (KeyloException ex)
        {
            _notify.Error(ex.Message);
        }
    }

    [RelayCommand]
    private async Task PushTo(ProviderItem? item)
    {
        if (_info is null || item is null || _keylo.Providers.Find(item.Id) is not { } provider) return;

        IsBusy = true;
        try
        {
            var settings = _keylo.Config.Providers.GetValueOrDefault(provider.Id) ?? new Dictionary<string, string>();
            var status = await provider.GetStatusAsync(settings);
            if (!status.Ready)
            {
                _notify.Error($"{provider.DisplayName}: {status.Message}");
                return;
            }

            await _keylo.EnsureValueAccessAsync($"push '{_info.Name}' to {provider.DisplayName}");
            var result = await provider.PushAsync(_keylo.Store.Get(_info.Name), settings);
            if (result.Succeeded) _notify.Success($"{provider.DisplayName}: {result.Message}");
            else _notify.Error($"{provider.DisplayName}: {result.Message}");
        }
        catch (KeyloException ex)
        {
            _notify.Error(ex.Message);
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>Drops any value held in memory (on lock or selection change).</summary>
    public void Clear()
    {
        _hideTimer.Stop();
        Value = "";
        _binaryValue = null;
        IsValueVisible = false;
    }
}
