using System.Runtime.InteropServices;

namespace Keylo.Platform.Linux.Interop;

/// <summary>
/// The few libsecret (and GLib) calls Keylo uses to talk to the Secret Service (GNOME Keyring,
/// KWallet, KeePassXC…). libsecret handles the D-Bus session, encryption and unlock prompts.
/// </summary>
internal static unsafe class LibSecret
{
    private const string Secret = "libsecret-1.so.0";
    private const string GLib = "libglib-2.0.so.0";

    public const int SearchAll = 1 << 1, SearchUnlock = 1 << 2, SearchLoadSecrets = 1 << 3;

    [DllImport(Secret)] public static extern int secret_password_storev_sync(IntPtr schema, IntPtr attributes, IntPtr collection, string label, string password, IntPtr cancellable, out IntPtr error);
    [DllImport(Secret)] public static extern IntPtr secret_password_lookupv_sync(IntPtr schema, IntPtr attributes, IntPtr cancellable, out IntPtr error);
    [DllImport(Secret)] public static extern int secret_password_clearv_sync(IntPtr schema, IntPtr attributes, IntPtr cancellable, out IntPtr error);
    [DllImport(Secret)] public static extern IntPtr secret_password_searchv_sync(IntPtr schema, IntPtr attributes, int flags, IntPtr cancellable, out IntPtr error);
    [DllImport(Secret)] public static extern void secret_password_free(IntPtr password);
    [DllImport(Secret)] public static extern IntPtr secret_retrievable_get_attributes(IntPtr retrievable);
    [DllImport(Secret)] public static extern ulong secret_retrievable_get_modified(IntPtr retrievable);
    [DllImport(Secret)] public static extern IntPtr secret_retrievable_retrieve_secret_sync(IntPtr retrievable, IntPtr cancellable, out IntPtr error);
    [DllImport(Secret)] public static extern IntPtr secret_value_get_text(IntPtr value);
    [DllImport(Secret)] public static extern void secret_value_unref(IntPtr value);

    [DllImport(GLib)] private static extern IntPtr g_hash_table_new(IntPtr hash, IntPtr equal);
    [DllImport(GLib)] private static extern int g_hash_table_insert(IntPtr table, IntPtr key, IntPtr value);
    [DllImport(GLib)] public static extern IntPtr g_hash_table_lookup(IntPtr table, IntPtr key);
    [DllImport(GLib)] public static extern void g_hash_table_unref(IntPtr table);
    [DllImport(GLib)] public static extern void g_error_free(IntPtr error);
    [DllImport(GLib)] private static extern void g_list_free_full(IntPtr list, IntPtr free);
    [DllImport("libgobject-2.0.so.0")] public static extern void g_object_unref(IntPtr obj);

    private static readonly Lazy<(IntPtr Hash, IntPtr Equal, IntPtr Unref)> Functions = new(() =>
    {
        var glib = NativeLibrary.Load(GLib);
        var gobject = NativeLibrary.Load("libgobject-2.0.so.0");
        return (NativeLibrary.GetExport(glib, "g_str_hash"), NativeLibrary.GetExport(glib, "g_str_equal"), NativeLibrary.GetExport(gobject, "g_object_unref"));
    });

    /// <summary>A GHashTable of strings for an attribute query. Dispose frees the table and the strings.</summary>
    public sealed class Attributes : IDisposable
    {
        private readonly List<IntPtr> _strings = [];
        public IntPtr Table { get; }

        public Attributes(params (string Key, string Value)[] pairs)
        {
            Table = g_hash_table_new(Functions.Value.Hash, Functions.Value.Equal);
            foreach (var (key, value) in pairs)
            {
                var k = Marshal.StringToCoTaskMemUTF8(key);
                var v = Marshal.StringToCoTaskMemUTF8(value);
                _strings.Add(k);
                _strings.Add(v);
                g_hash_table_insert(Table, k, v);
            }
        }

        public void Dispose()
        {
            g_hash_table_unref(Table);
            foreach (var s in _strings) Marshal.FreeCoTaskMem(s);
        }
    }

    /// <summary>A string value from a GHashTable of strings (e.g. an item's attributes).</summary>
    public static string? Lookup(IntPtr table, string key)
    {
        var k = Marshal.StringToCoTaskMemUTF8(key);
        try
        {
            var value = g_hash_table_lookup(table, k);
            return value == IntPtr.Zero ? null : Marshal.PtrToStringUTF8(value);
        }
        finally
        {
            Marshal.FreeCoTaskMem(k);
        }
    }

    /// <summary>The items of a GList (each node is { data, next, prev }).</summary>
    public static IEnumerable<IntPtr> Items(IntPtr list)
    {
        for (var node = list; node != IntPtr.Zero; node = Marshal.ReadIntPtr(node, IntPtr.Size))
            yield return Marshal.ReadIntPtr(node);
    }

    /// <summary>Frees a GList of GObjects, such as search results.</summary>
    public static void FreeObjectList(IntPtr list)
    {
        if (list != IntPtr.Zero) g_list_free_full(list, Functions.Value.Unref);
    }

    /// <summary>A GError's message (and frees it); null when there was no error.</summary>
    public static string? TakeError(IntPtr error)
    {
        if (error == IntPtr.Zero) return null;
        // struct GError { GQuark domain; gint code; gchar *message; }
        var message = Marshal.PtrToStringUTF8(Marshal.ReadIntPtr(error, 8)) ?? "unknown error";
        g_error_free(error);
        return message;
    }

    /// <summary>
    /// A SecretSchema (name, flags, up to 32 string attributes) in unmanaged memory, kept for the
    /// process's life. Layout: name, flags, attributes[32] of { name, type }, then reserved fields.
    /// </summary>
    public static IntPtr Schema(string name, params string[] attributes)
    {
        var size = IntPtr.Size * 2 + 32 * IntPtr.Size * 2 + IntPtr.Size * 8;
        var schema = Marshal.AllocHGlobal(size);
        new Span<byte>((void*)schema, size).Clear();
        Marshal.WriteIntPtr(schema, 0, Marshal.StringToCoTaskMemUTF8(name));
        Marshal.WriteInt32(schema, IntPtr.Size, 0); // SECRET_SCHEMA_NONE: match on the schema name too
        for (var i = 0; i < attributes.Length; i++)
        {
            var offset = IntPtr.Size * 2 + i * IntPtr.Size * 2;
            Marshal.WriteIntPtr(schema, offset, Marshal.StringToCoTaskMemUTF8(attributes[i]));
            Marshal.WriteInt32(schema, offset + IntPtr.Size, 0); // SECRET_SCHEMA_ATTRIBUTE_STRING
        }
        return schema;
    }
}
