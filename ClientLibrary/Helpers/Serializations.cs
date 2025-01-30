using System.Text.Json;

namespace ClientLibrary.Helpers;

public static class Serializations
{
    public static string Serialize<T>(T obj) 
        => JsonSerializer.Serialize(obj);

    public static T? Deserialize<T>(string json)
        => JsonSerializer.Deserialize<T>(json);

    public static IList<T>? DeserializeList<T>(string json)
        => JsonSerializer.Deserialize<IList<T>>(json);
}
