using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Keylo.App.Services;
using Keylo.Core;
using Keylo.Core.Platform;

namespace Keylo.App.ViewModels;

public sealed record ProviderItem(string Id, string DisplayName, bool IsConfigured)
{
    public string PushLabel => $"Push to {DisplayName}";

    public string ToolTip => IsConfigured
        ? $"Copy this secret into {DisplayName}"
        : $"Set up {DisplayName} first: Settings → Vault providers";
}

/// <summary>The right-hand panel: viewing, editing or creating one secret.</summary>
public sealed partial class SecretDetailViewModel : ObservableObject
{
    private readonly KeyloService _keylo;
    private readonly IUserNotifier _notify;
    private readonly Func<string?, Task> _reload;
    private readonly IUiTimer _hideTimer;

    private SecretInfo? _info;
    private byte[]? _binaryValue;
    private bool _valuesLoaded;
    private bool _loading;
    private LinkedSecrets.Link? _link;

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

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Type), nameof(IsTyped), nameof(IsPlain), nameof(TypeName), nameof(ShowKey), nameof(ShowFieldEditors), nameof(Symbol), nameof(Image), nameof(HasImage), nameof(TileBrush))]
    private TypeChoice? _selectedType;

    public SecretDetailViewModel(KeyloService keylo, IUserNotifier notify, Func<string?, Task> reload, SecretInfo? info)
    {
        _keylo = keylo;
        _notify = notify;
        _reload = reload;
        _hideTimer = Ui.Host.CreateTimer(TimeSpan.FromSeconds(30), HideValue);

        Categories = new ObservableCollection<string>(keylo.Store.Categories());
        Providers = new ObservableCollection<ProviderItem>(keylo.Providers.All.Select(p => new ProviderItem(p.Id, p.DisplayName,
            p.IsConfigured(keylo.Config.Providers.GetValueOrDefault(p.Id) ?? new Dictionary<string, string>()))));
        TypeChoices = new ObservableCollection<TypeChoice>([new TypeChoice(null), .. keylo.Types.Select(t => new TypeChoice(t))]);

        if (info is null)
        {
            IsNew = true;
            IsEditing = true;
            IsValueVisible = true;
            _loading = true;
            SelectedType = TypeChoices[0];
            _loading = false;
        }
        else
        {
            Load(info);
        }
    }

    public bool IsNew { get; }

    /// <summary>Pinned secrets lead the Home list.</summary>
    public bool IsPinned => _info is not null && _keylo.Activity.IsPinned(_info.Name);

    [RelayCommand]
    private async Task TogglePin()
    {
        if (_info is null) return;
        var pin = !IsPinned;
        _keylo.Activity.SetPinned(_info.Name, pin);
        _notify.Success(pin ? $"Pinned '{_info.Name}' to Home." : $"Unpinned '{_info.Name}'.");
        await _reload(_info.Name);
    }

    private void Used(string action)
    {
        if (_info is not null) _keylo.Activity.RecordUse(_info.Name, action);
    }
    public bool IsViewing => !IsEditing;
    public string Title => IsNew ? "New secret" : Name;
    public ObservableCollection<string> Categories { get; }
    public ObservableCollection<ProviderItem> Providers { get; }
    public ObservableCollection<TypeChoice> TypeChoices { get; }

    /// <summary>A typed secret's fields; empty for a plain secret.</summary>
    public ObservableCollection<FieldViewModel> Fields { get; } = [];

    public SecretTypeDefinition? Type => SelectedType?.Definition;

    /// <summary>A link to an item in another vault: values are read live; only name, category, notes and icon are edited here.</summary>
    public bool IsLinked => _link is not null;
    public bool IsNotLinked => !IsLinked;
    public bool ShowFieldEditors => IsTyped && !IsLinked;

    public string LinkDescription => _link is null ? "" :
        $"Linked to “{_link.Title}” in {_keylo.Providers.FindLinked(_link.Target.Provider)?.DisplayName ?? _link.Target.Provider}" +
        (_link.Where is { Length: > 0 } where ? $" · {where}" : "") +
        (_link.OnlyField is { } only ? $" · only its {_link.Fields.FirstOrDefault(f => f.Id == only)?.Label ?? only}" : "");
    public bool IsTyped => Type is not null;
    public bool IsPlain => !IsTyped;
    public string? TypeName => Type?.Name;

    public string MaskedValue => IsValueVisible ? Value : "••••••••••••••••";

    /// <summary>Header tile: own icon/colour, falling back to the category's, then the type's, then Keylo's default.</summary>
    public object? Symbol => Ui.Host.Symbol(Icon ?? _keylo.Categories.StyleOf(Category)?.Icon ?? Type?.Icon, "Key24");

    public object? Image => Ui.Host.Image(Icon ?? _keylo.Categories.StyleOf(Category)?.Icon ?? Type?.Icon);

    public bool HasImage => Image is not null;

    public object TileBrush => HasImage ? Ui.Host.Transparent :
        Ui.Host.Tile(IconPalette.FirstColor(Color, _keylo.Categories.StyleOf(Category)?.Color, Type?.Color) ?? "#6366F1");
    public int ValueLength => Value.Length;

    public string UpdatedText => _info is null ? "" : _info.UpdatedAt.LocalDateTime.ToString("MMM d, yyyy  h:mm tt");
    public string SizeText => _info switch
    {
        null => "",
        { Size: 1 } => "1 byte",
        { Size: < 1024 } => $"{_info.Size} bytes",
        _ => $"{_info.Size / 1024.0:0.#} KB",
    };
    public string StorageText => _info?.Storage == StorageKind.EncryptedFile
        ? $"Encrypted file ({KeyloPlatform.Current.FileProtectionName})"
        : KeyloPlatform.Current.StoreName;
    public bool HasUsername => !string.IsNullOrEmpty(_info?.Username);
    public bool ShowKey => IsPlain && HasUsername;
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

    partial void OnIsValueVisibleChanged(bool value)
    {
        foreach (var field in Fields) field.Revealed = value;
    }

    /// <summary>Switching type while editing carries values across: same-named fields, main value and username.</summary>
    partial void OnSelectedTypeChanged(TypeChoice? oldValue, TypeChoice? newValue)
    {
        if (_loading) return;

        var current = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string? main, user;
        if (oldValue?.Definition is { } oldType)
        {
            foreach (var field in Fields.Where(f => f.HasValue)) current[field.Id] = field.Value;
            main = oldType.Primary is { } p ? current.GetValueOrDefault(p.Id) : null;
            user = oldType.UsernameField is { } u ? current.GetValueOrDefault(u.Id) : null;
        }
        else
        {
            main = IsBinary ? null : Value;
            user = Username;
        }

        if (newValue?.Definition is { } newType)
        {
            if (newType.Primary is { } primary && !current.ContainsKey(primary.Id) && !string.IsNullOrEmpty(main)) current[primary.Id] = main;
            if (newType.UsernameField is { } userField && !current.ContainsKey(userField.Id) && !string.IsNullOrEmpty(user)) current[userField.Id] = user;
            BuildFields(newType, current);
        }
        else
        {
            Fields.Clear();
            Value = main ?? "";
            Username = user ?? "";
        }
        IsValueVisible = true;
    }

    private void Load(SecretInfo info)
    {
        _info = info;
        _link = LinkedSecrets.Read(info);
        _loading = true;
        SelectedType = _link is { } link
            ? new TypeChoice(LinkedSecrets.AsType(link, _keylo.Providers.FindLinked(link.Target.Provider)?.DisplayName ?? link.Target.Provider))
            : TypeChoices.FirstOrDefault(t => t.Id is not null && t.Id.Equals(info.Type, StringComparison.OrdinalIgnoreCase)) ?? TypeChoices[0];
        _loading = false;
        if (_link is not null) Providers.Clear(); // Pushing a link elsewhere makes no sense.
        OnPropertyChanged(nameof(IsLinked));
        OnPropertyChanged(nameof(IsNotLinked));
        OnPropertyChanged(nameof(ShowFieldEditors));
        OnPropertyChanged(nameof(LinkDescription));

        Name = info.Name;
        Category = info.Category ?? "";
        Username = info.Username ?? "";
        Notes = info.Notes ?? "";
        Icon = info.Icon;
        Color = info.Color;
        Value = "";
        IsValueVisible = false;
        IsBinary = false;
        _valuesLoaded = false;

        // Non-secret fields are metadata, shown without unlocking; secret ones load on demand.
        var known = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (Type is { } type)
        {
            if (type.UsernameField is { } user && info.Username is not null) known[user.Id] = info.Username;
            foreach (var (id, value) in info.Fields ?? new Dictionary<string, string>()) known[id] = value;
            BuildFields(type, known);
        }
        else
        {
            Fields.Clear();
        }

        OnPropertyChanged(nameof(UpdatedText));
        OnPropertyChanged(nameof(SizeText));
        OnPropertyChanged(nameof(StorageText));
        OnPropertyChanged(nameof(HasUsername));
        OnPropertyChanged(nameof(ShowKey));
        OnPropertyChanged(nameof(HasNotes));
        OnPropertyChanged(nameof(HasCategory));
        OnPropertyChanged(nameof(Title));
    }

    private void BuildFields(SecretTypeDefinition type, IReadOnlyDictionary<string, string> values)
    {
        Fields.Clear();
        foreach (var definition in type.Fields)
            Fields.Add(new FieldViewModel(definition, CopyFieldAsync) { Value = values.GetValueOrDefault(definition.Id) ?? "", Revealed = IsValueVisible });
    }

    /// <summary>
    /// Reads the value after an access check. Returns false when it couldn't be read. With
    /// <paramref name="derive"/>, a database's connection string is built from its fields if none is stored.
    /// </summary>
    private async Task<bool> LoadValueAsync(string why, bool derive = true)
    {
        if (_info is null) return true;
        try
        {
            await _keylo.EnsureValueAccessAsync($"{why} '{_info.Name}'");
            if (_link is not null)
            {
                var values = await _keylo.ResolveLinkedAsync(_info);
                foreach (var field in Fields) field.Value = values.GetValueOrDefault(field.Id) ?? "";
                _valuesLoaded = true;
                return true;
            }

            var bytes = _keylo.Store.Get(_info.Name).Value;

            if (Type is { } type && string.Equals(_info.Type, type.Id, StringComparison.OrdinalIgnoreCase))
            {
                var fields = TypedSecrets.ReadFields(type, _info, bytes, derive);
                var stored = derive ? TypedSecrets.ReadFields(type, _info, bytes, derive: false) : fields;
                foreach (var field in Fields)
                {
                    field.Value = fields.GetValueOrDefault(field.Id) ?? "";
                    field.IsDerived = !stored.ContainsKey(field.Id) && fields.ContainsKey(field.Id);
                }
                _valuesLoaded = true;
                return true;
            }

            var text = KeyloService.DecodeText(bytes);
            IsBinary = text is null;
            _binaryValue = text is null ? bytes : null;
            Value = text ?? $"Binary value ({bytes.Length} bytes) — use Export or Replace from file";
            _valuesLoaded = true;
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
        Used("viewed");
        IsValueVisible = true;
        _hideTimer.Stop();
        _hideTimer.Start();
    }

    private void HideValue()
    {
        _hideTimer.Stop();
        IsValueVisible = false;
        if (IsEditing) return;
        Value = "";
        ForgetSecretFields();
    }

    private void ForgetSecretFields()
    {
        foreach (var field in Fields.Where(f => f.IsSecret)) field.Value = "";
        _valuesLoaded = false;
    }

    [RelayCommand]
    private async Task CopyValue()
    {
        if (_info is null) return;
        if (IsTyped)
        {
            if (Fields.FirstOrDefault(f => f.Definition == Type!.Primary) is { } primary) await CopyFieldAsync(primary);
            return;
        }

        var visible = IsValueVisible;
        if (!await LoadValueAsync("copy")) return;
        if (IsBinary)
        {
            _notify.Error("Binary values can't be copied. Use Export instead.");
            return;
        }

        _keylo.CopyToClipboard(Value);
        Used("copied");
        if (!visible) Value = "";
        _notify.Success($"Copied. Clears from the clipboard in {_keylo.Config.ClipboardSeconds}s.");
    }

    private async Task CopyFieldAsync(FieldViewModel field)
    {
        var loadedHere = false;
        if (field.IsSecret && !_valuesLoaded && !IsEditing)
        {
            if (!await LoadValueAsync("copy")) return;
            loadedHere = true;
        }

        if (!field.HasValue)
        {
            _notify.Info($"{field.Label} is empty.");
        }
        else
        {
            _keylo.CopyToClipboard(field.Value);
            Used("copied");
            _notify.Success(field.IsSecret ? $"{field.Label} copied. Clears from the clipboard in {_keylo.Config.ClipboardSeconds}s." : $"{field.Label} copied.");
        }

        if (loadedHere && !IsValueVisible) ForgetSecretFields();
    }

    [RelayCommand]
    private void CopyUsername()
    {
        if (string.IsNullOrEmpty(_info?.Username)) return;
        _keylo.CopyToClipboard(_info.Username);
        Used("copied");
        _notify.Success("Key copied.");
    }

    [RelayCommand]
    private async Task Edit()
    {
        // A link's values stay in its vault; editing it only changes name, category, notes and icon.
        if (_link is null && !await LoadValueAsync("edit", derive: false)) return;
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
        var password = PasswordGenerator.Generate(GeneratorLength, GeneratorSymbols);
        if (IsTyped)
        {
            var target = Fields.FirstOrDefault(f => f.Definition.Kind == FieldKind.Password);
            if (target is null)
            {
                _notify.Info($"{Type!.Name} has no password field to generate.");
                return;
            }
            target.Value = password;
            IsValueVisible = true;
            return;
        }

        Value = password;
        IsValueVisible = true;
        IsBinary = false;
        _binaryValue = null;
    }

    [RelayCommand]
    private async Task ReplaceFromFile()
    {
        var picked = await Ui.Host.PickFilesAsync(IsTyped ? $"Load {Type!.Primary?.Label ?? "value"} from file" : "Replace value from file", multiple: false);
        if (picked.Count == 0) return;
        var fileName = picked[0];

        var bytes = File.ReadAllBytes(fileName);
        var text = KeyloService.DecodeText(bytes);
        if (IsTyped)
        {
            if (text is null)
            {
                _notify.Error("That file isn't text. Typed secrets hold text; use a plain secret for binary files.");
                return;
            }
            if (Fields.FirstOrDefault(f => f.Definition == Type!.Primary) is { } primary) primary.Value = text;
            IsValueVisible = true;
            return;
        }

        IsBinary = text is null;
        _binaryValue = text is null ? bytes : null;
        Value = text ?? $"Binary value ({bytes.Length} bytes) from {Path.GetFileName(fileName)}";
        IsValueVisible = text is not null;
    }

    [RelayCommand]
    private async Task Export()
    {
        if (_info is null) return;
        if (await Ui.Host.PickSaveFileAsync("Export value", _info.Name + (IsTyped || IsLinked ? ".json" : "")) is not { } fileName) return;

        try
        {
            await _keylo.EnsureValueAccessAsync($"export '{_info.Name}'");
            if (_link is not null)
            {
                await File.WriteAllBytesAsync(fileName, JsonSerializer.SerializeToUtf8Bytes(await _keylo.ResolveLinkedAsync(_info), new JsonSerializerOptions { WriteIndented = true }));
                _notify.Success($"Exported to {fileName}. That file is not encrypted.");
                return;
            }
            var secret = _keylo.Store.Get(_info.Name);
            // Typed secrets export every field as JSON; plain ones their raw bytes.
            var bytes = Type is { } type && _info.Type is not null
                ? JsonSerializer.SerializeToUtf8Bytes(TypedSecrets.ReadFields(type, _info, secret.Value, derive: false), new JsonSerializerOptions { WriteIndented = true })
                : secret.Value;
            await File.WriteAllBytesAsync(fileName, bytes);
            Used("exported");
            _notify.Success($"Exported to {fileName}. That file is not encrypted.");
        }
        catch (Exception ex) when (ex is KeyloException or IOException or UnauthorizedAccessException)
        {
            _notify.Error(ex.Message);
        }
    }

    [RelayCommand]
    private async Task Save()
    {
        SecretDraft draft;
        if (_link is not null)
        {
            draft = LinkedSecrets.Draft(Name, _link, Category, Notes, Icon, Color);
        }
        else if (Type is { } type)
        {
            var values = Fields.ToDictionary(f => f.Id, f => (string?)f.Value, StringComparer.OrdinalIgnoreCase);
            if (type.Primary is { } primary && string.IsNullOrEmpty(values.GetValueOrDefault(primary.Id)))
            {
                _notify.Error($"Enter the {primary.Label.ToLowerInvariant()}.");
                return;
            }
            try
            {
                draft = TypedSecrets.Draft(type, Name, values, Category, Notes, Icon, Color);
            }
            catch (KeyloException ex)
            {
                _notify.Error(ex.Message);
                return;
            }
        }
        else
        {
            var value = IsBinary && _binaryValue is not null ? _binaryValue : Encoding.UTF8.GetBytes(Value);
            if (value.Length == 0)
            {
                _notify.Error("Enter a value.");
                return;
            }
            draft = new SecretDraft(Name, value, Category, Username, Notes, Icon, Color);
        }

        IsBusy = true;
        try
        {
            await _keylo.EnsureBrowseAsync();
            var saved = _keylo.Store.Save(draft, originalName: IsNew ? null : _info?.Name);
            if (!IsNew && _info is not null) _keylo.Activity.Renamed(_info.Name, saved.Name);

            _notify.Success(IsNew ? $"Added '{saved.Name}'." : $"Saved '{saved.Name}'.");
            Value = "";
            ForgetSecretFields();
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
        var confirmed = _link is { } link
            ? await _notify.ConfirmAsync("Remove link",
                $"Remove '{_info.Name}' from Keylo? Only the link is removed — “{link.Title}” stays in {_keylo.Providers.FindLinked(link.Target.Provider)?.DisplayName ?? link.Target.Provider}.",
                "Remove link")
            : await _notify.ConfirmAsync("Delete secret", $"Delete '{_info.Name}'? This can't be undone.", "Delete");
        if (!confirmed) return;

        try
        {
            await _keylo.EnsureBrowseAsync();
            _keylo.Store.Delete(_info.Name);
            _keylo.Activity.Removed([_info.Name]);
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

            // Show exactly where it goes, and whether it replaces an earlier copy, before anything is sent.
            var preview = await provider.PreviewAsync(_info.Name, settings);
            var detail = string.Join(" · ", new[] { TypeName ?? "Plain secret", HasCategory ? Category : null }.Where(s => !string.IsNullOrEmpty(s)));
            if (!await _notify.ConfirmPushAsync(new PushConfirmation(
                    provider.DisplayName, _info.Name, detail, Symbol, Image, TileBrush,
                    preview.Destination ?? preview.Target, preview.DestinationDetail ?? "", preview.Exists)))
                return;

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
        ForgetSecretFields();
    }
}
