using System.Collections;
using System.Collections.Specialized;
using System.ComponentModel;

namespace Keylo.App.ViewModels;

/// <summary>
/// Calls back whenever a watched object raises PropertyChanged or a watched collection changes
/// (new items in it are watched too), for dirty tracking. Nested collections are watched by passing
/// them in as well.
/// </summary>
internal sealed class ChangeWatcher(Action changed)
{
    private readonly HashSet<object> _watched = new(ReferenceEqualityComparer.Instance);

    public void Watch(object? target)
    {
        if (target is null || !_watched.Add(target)) return;

        if (target is INotifyPropertyChanged item)
            item.PropertyChanged += (_, _) => changed();

        if (target is INotifyCollectionChanged collection)
        {
            collection.CollectionChanged += (_, e) =>
            {
                foreach (var added in e.NewItems ?? Array.Empty<object>()) Watch(added);
                changed();
            };
            foreach (var existing in (IEnumerable)target) Watch(existing);
        }
    }
}
