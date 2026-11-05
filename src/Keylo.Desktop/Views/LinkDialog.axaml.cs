using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Keylo.App.Services;
using Keylo.Core;
using Keylo.Core.Providers;

namespace Keylo.Desktop.Views;

/// <summary>Searches a linked vault (1Password, AWS Secrets Manager or a plugin's) and creates a Keylo secret that points at an item.</summary>
public partial class LinkDialog : DialogWindow
{
    public sealed record ResultRow(LinkedItemSummary Item)
    {
        public string Title => Item.Title;
        public string Subtitle => string.Join(" · ", new[] { Item.VaultName, Item.Location, Item.Category }.Where(s => !string.IsNullOrEmpty(s)));
    }

    public sealed record FieldChoice(LinkedField? Field, string Label);

    private readonly KeyloService _keylo = null!;
    private IReadOnlyList<LinkedField> _fields = [];
    private IReadOnlyList<LinkedItemSummary> _items = [];
    private string? _suggestedCategory;
    private int _searchId;
    private bool _opened;

    public LinkDialog() => InitializeComponent();

    public LinkDialog(KeyloService keylo)
    {
        InitializeComponent();
        _keylo = keylo;

        var several = OperatingSystem.IsMacOS() ? "⌘ or Shift+click" : "Ctrl or Shift+click";
        Intro.Text = $"{several} to link several items at once. Keylo stores only a reference. The value is read from the vault each time it's used — " +
                     "never copied — so changes there apply at once. Access keys, approvals, redaction and the audit log work as for any secret.";

        ProviderBox.ItemsSource = keylo.Providers.Linked;
        ProviderBox.SelectedIndex = 0;
        ProviderBox.IsVisible = keylo.Providers.Linked.Count > 1;
        CategoryBox.ItemsSource = keylo.Store.Categories();

        Opened += async (_, _) =>
        {
            _opened = true;
            SearchBox.Focus();
            await SearchAsync();
        };
    }

    /// <summary>The new secret's name, once linked.</summary>
    public string? CreatedName { get; private set; }

    /// <summary>How many secrets were linked (several when more than one item was chosen).</summary>
    public int LinkedCount { get; private set; } = 1;

    private ILinkedVaultProvider? Provider => ProviderBox.SelectedItem as ILinkedVaultProvider;

    private IReadOnlyDictionary<string, string> ConfiguredSettings =>
        Provider is { } p ? _keylo.Config.Providers.GetValueOrDefault(p.Id) ?? new Dictionary<string, string>() : new Dictionary<string, string>();

    /// <summary>The provider's settings, with the profile and region picked here for AWS.</summary>
    private IReadOnlyDictionary<string, string> Settings => IsAws
        ? AwsLinkScope.Apply(ConfiguredSettings, ProfileBox.SelectedItem as AwsProfileChoice, RegionBox.SelectedItem as string)
        : ConfiguredSettings;

    private bool IsAws => Provider?.Id == AwsLinkScope.ProviderId;

    /// <summary>The AWS environment picked, if any: links made then are per environment (used as name@env).</summary>
    private string? Environment => IsAws ? (ProfileBox.SelectedItem as AwsProfileChoice)?.Environment : null;
    private bool _awsReady, _settingAws;

    private async void OnProviderChanged(object? sender, SelectionChangedEventArgs e)
    {
        ShowAwsScope();
        if (_opened) await SearchAsync();
    }

    /// <summary>For AWS: profile and region pickers, starting from the configured ones.</summary>
    private void ShowAwsScope()
    {
        AwsPanel.IsVisible = IsAws;
        if (!IsAws || _awsReady) return;
        _awsReady = _settingAws = true;
        var profiles = AwsLinkScope.Profiles(ConfiguredSettings);
        var profile = AwsLinkScope.Initial(profiles, ConfiguredSettings);
        ProfileBox.ItemsSource = profiles;
        ProfileBox.SelectedItem = profile;
        RegionBox.ItemsSource = AwsLinkScope.Regions();
        RegionBox.SelectedItem = AwsLinkScope.InitialRegion(profile, ConfiguredSettings);
        RegionBox.IsEnabled = profile.Environment is null;
        _settingAws = false;
    }

    private async void OnProfileChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (_settingAws) return;
        // A profile brings its own region; an environment fixes it.
        RegionBox.IsEnabled = Environment is null;
        if (ProfileBox.SelectedItem is AwsProfileChoice { Region: { } region })
        {
            _settingAws = true;
            RegionBox.SelectedItem = region;
            _settingAws = false;
        }
        if (_opened) await SearchAsync();
    }

    private async void OnRegionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (!_settingAws && _opened) await SearchAsync();
    }

    private async void OnSearch(object? sender, RoutedEventArgs e) => await SearchAsync();

    private async void OnSearchKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) await SearchAsync();
    }

    private async Task SearchAsync()
    {
        if (Provider is not { } provider) return;
        var id = ++_searchId;
        SetBusy(true);
        Status.Text = "";
        try
        {
            var items = await provider.SearchAsync(SearchBox.Text ?? "", Settings);
            if (id != _searchId) return;
            _items = items;
            Results.ItemsSource = items.Select(i => new ResultRow(i)).ToList();
            Status.Text = items.Count == 0 ? "Nothing matches." : $"{items.Count} item{(items.Count == 1 ? "" : "s")}. Choose one to link.";
        }
        catch (KeyloException ex)
        {
            if (id == _searchId) Status.Text = ex.Message;
        }
        finally
        {
            if (id == _searchId) SetBusy(false);
        }
    }

    private List<LinkedItemSummary> Selected => Results.SelectedItems?.OfType<ResultRow>().Select(r => r.Item).ToList() ?? [];

    private bool SeveralLocations => _items.Select(i => i.Location).Distinct().Count() > 1;

    private async void OnItemSelected(object? sender, SelectionChangedEventArgs e)
    {
        if (Provider is not { } provider) return;
        var selected = Selected;
        LinkButton.IsEnabled = false;
        LinkText.Text = selected.Count > 1 ? $"Link {selected.Count} items" : "Link";
        if (selected.Count == 0)
        {
            Details.IsVisible = false;
            return;
        }

        // Several items: each gets all its fields, a name from its title, and its own default category
        // (or the one typed here).
        if (selected.Count > 1)
        {
            NamePanel.IsVisible = FieldPanel.IsVisible = false;
            if (CategoryBox.Text == _suggestedCategory) CategoryBox.Text = _suggestedCategory = "";
            CategoryHint.IsVisible = true;
            FieldsText.Text = $"{selected.Count} items, each linked with all its fields and named after its title.";
            Details.IsVisible = true;
            LinkButton.IsEnabled = true;
            return;
        }

        var item = selected[0];
        NamePanel.IsVisible = FieldPanel.IsVisible = true;
        CategoryHint.IsVisible = false;
        Details.IsVisible = false;
        SetBusy(true);
        try
        {
            _fields = await provider.DescribeAsync(Target(item), Settings);
            NameBox.Text = SuggestName(item.Title, new HashSet<string>());

            // Suggest "1Password · Vault" (or the provider's equivalent), unless the user typed their own category.
            if (string.IsNullOrWhiteSpace(CategoryBox.Text) || CategoryBox.Text == _suggestedCategory)
            {
                _suggestedCategory = LinkedSecrets.DefaultCategory(provider.DisplayName, item, SeveralLocations);
                CategoryBox.Text = _suggestedCategory;
            }
            FieldBox.ItemsSource = new[] { new FieldChoice(null, "All fields") }
                .Concat(_fields.Select(f => new FieldChoice(f, $"Only {f.Label}{(f.Secret ? "" : " (not secret)")}")))
                .ToList();
            FieldBox.SelectedIndex = 0;
            FieldsText.Text = _fields.Count == 0 ? "This item has no fields." : "Fields: " + string.Join(", ", _fields.Select(f => f.Secret ? $"{f.Label} 🔒" : f.Label));
            Details.IsVisible = true;
            LinkButton.IsEnabled = _fields.Count > 0;
            Status.Text = "";
        }
        catch (KeyloException ex)
        {
            Status.Text = ex.Message;
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void OnLink(object? sender, RoutedEventArgs e)
    {
        if (Provider is not { } provider) return;
        var selected = Selected;
        if (selected.Count == 0) return;

        var typedCategory = string.IsNullOrWhiteSpace(CategoryBox.Text) ? null : CategoryBox.Text.Trim();
        LinkButton.IsEnabled = false;
        try
        {
            await _keylo.EnsureBrowseAsync();

            if (selected.Count == 1)
            {
                var name = SecretStore.NormalizeName(NameBox.Text ?? "");
                if (_keylo.Store.Exists(name)) throw new SecretExistsException(name);
                var only = (FieldBox.SelectedItem as FieldChoice)?.Field?.Id;
                _keylo.Store.Save(LinkedSecrets.Draft(name, MakeLink(selected[0], _fields, only), typedCategory));
                CreatedName = name;
                Close();
                return;
            }

            SetBusy(true);
            var taken = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var failed = new List<string>();
            foreach (var item in selected)
            {
                try
                {
                    var fields = await provider.DescribeAsync(Target(item), Settings);
                    var name = SuggestName(item.Title, taken);
                    var category = typedCategory ?? LinkedSecrets.DefaultCategory(provider.DisplayName, item, SeveralLocations);
                    _keylo.Store.Save(LinkedSecrets.Draft(name, MakeLink(item, fields, null), category));
                    taken.Add(name);
                    CreatedName ??= name;
                }
                catch (KeyloException ex)
                {
                    failed.Add($"{item.Title}: {ex.Message}");
                }
            }

            LinkedCount = taken.Count;
            if (failed.Count == 0)
            {
                Close();
                return;
            }
            Status.Text = $"Linked {taken.Count} of {selected.Count}. " + string.Join(" ", failed);
            if (taken.Count > 0) CancelButton.Content = "Close";
        }
        catch (KeyloException ex)
        {
            Status.Text = ex.Message;
        }
        finally
        {
            SetBusy(false);
            LinkButton.IsEnabled = Selected.Count > 0;
        }
    }

    private LinkedSecrets.Link MakeLink(LinkedItemSummary item, IReadOnlyList<LinkedField> fields, string? only)
    {
        var where = Environment is not null ? "per environment"
            : string.Join(" · ", new[] { item.VaultName, item.Location }.Where(x => !string.IsNullOrEmpty(x)));
        return new LinkedSecrets.Link(Target(item), item.Title, where, fields, only);
    }

    private void OnCancel(object? sender, RoutedEventArgs e) => Close();

    private LinkTarget Target(LinkedItemSummary item) => Environment is not null
        ? new(Provider!.Id, item.Title, null, LinkedSecrets.PerEnvironment)
        : new(Provider!.Id, item.ItemId, item.VaultId, item.Location);

    /// <summary>"GitHub (work)" → "github-work" style slug, unique among existing secrets and <paramref name="taken"/>.</summary>
    private string SuggestName(string title, IReadOnlySet<string> taken)
    {
        var name = new string(title.Trim().ToLowerInvariant().Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.' ? c : '-').ToArray()).Trim('-');
        while (name.Contains("--")) name = name.Replace("--", "-");
        if (name.Length == 0) name = "linked";
        if (name.Length > 100) name = name[..100];
        var candidate = name;
        for (var n = 2; taken.Contains(candidate) || _keylo.Store.Exists(candidate); n++) candidate = $"{name}-{n}";
        return candidate;
    }

    private void SetBusy(bool busy)
    {
        if (busy) BusyText.Text = $"Waiting for {Provider?.DisplayName ?? "the vault"}… approve it if it asks.";
        Busy.IsVisible = busy;
        Results.Opacity = busy ? 0.3 : 1;
        Results.IsEnabled = !busy;
        SearchButton.IsEnabled = !busy;
    }
}
