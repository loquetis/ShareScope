namespace ShareScope.Core;

public static class RightsSummarizer
{
    public const uint FileReadData = 0x0001;
    public const uint FileWriteData = 0x0002;
    public const uint FileAppendData = 0x0004;
    public const uint FileReadEa = 0x0008;
    public const uint FileWriteEa = 0x0010;
    public const uint FileExecute = 0x0020;
    public const uint FileDeleteChild = 0x0040;
    public const uint FileReadAttributes = 0x0080;
    public const uint FileWriteAttributes = 0x0100;
    public const uint Delete = 0x0001_0000;
    public const uint ReadControl = 0x0002_0000;
    public const uint WriteDac = 0x0004_0000;
    public const uint WriteOwner = 0x0008_0000;
    public const uint Synchronize = 0x0010_0000;

    public const uint GenericAll = 0x1000_0000;
    public const uint GenericExecute = 0x2000_0000;
    public const uint GenericWrite = 0x4000_0000;
    public const uint GenericRead = 0x8000_0000;

    public const uint FullControl = 0x001F_01FF;
    public const uint Modify = 0x0013_01BF;
    public const uint ReadAndExecute = 0x0012_00A9;
    public const uint Read = 0x0012_0089;
    public const uint Write = 0x0000_0116;
    public const uint FileGenericWrite = 0x0012_0116;

    private const uint GenericBits = GenericAll | GenericExecute | GenericWrite | GenericRead;
    private const uint WriteCapabilityBits =
        FileWriteData | FileAppendData | FileWriteEa | FileWriteAttributes | FileDeleteChild | Delete | WriteDac | WriteOwner;
    private const uint ReadCapabilityBits = FileReadData | FileReadEa | FileReadAttributes;

    public static RightsSummary Summarize(uint mask, PermissionLayer layer)
    {
        if ((mask & GenericAll) != 0)
            return Make("Full Control", full: true, change: true, write: true, read: true, special: false);

        var expanded = mask;
        if ((mask & GenericRead) != 0)
            expanded |= Read;
        if ((mask & GenericWrite) != 0)
            expanded |= FileGenericWrite;
        if ((mask & GenericExecute) != 0)
            expanded |= ReadAndExecute;

        var canonical = expanded & ~(Synchronize | GenericBits);
        var fullBits = FullControl & ~Synchronize;
        var modifyBits = Modify & ~Synchronize;
        var readExecuteBits = ReadAndExecute & ~Synchronize;
        var readBits = Read & ~Synchronize;
        var genericWriteBits = FileGenericWrite & ~Synchronize;

        var writeCapable = (canonical & WriteCapabilityBits) != 0;
        var canRead = (canonical & ReadCapabilityBits) != 0;

        if (canonical == fullBits)
            return Make("Full Control", full: true, change: true, write: true, read: true, special: false);

        if (canonical == modifyBits)
        {
            var text = layer == PermissionLayer.Share ? "Change" : "Modify";
            return Make(text, full: false, change: true, write: true, read: true, special: false);
        }

        if (canonical == readExecuteBits && !writeCapable)
        {
            var text = layer == PermissionLayer.Share ? "Read" : "Read & Execute";
            return Make(text, full: false, change: false, write: false, read: true, special: false);
        }

        if (canonical == readBits && !writeCapable)
            return Make("Read", full: false, change: false, write: false, read: true, special: false);

        if ((canonical == Write || canonical == genericWriteBits) && !canRead)
            return Make("Write", full: false, change: false, write: true, read: false, special: false);

        if (canonical == 0)
            return Make("None", full: false, change: false, write: false, read: false, special: false);

        var parts = new List<string>();
        if ((canonical & (FileWriteData | FileAppendData | FileWriteEa | FileWriteAttributes | FileDeleteChild)) != 0)
            parts.Add("Write");
        if ((canonical & Delete) != 0)
            parts.Add("Delete");
        if ((canonical & WriteDac) != 0)
            parts.Add("Change permissions");
        if ((canonical & WriteOwner) != 0)
            parts.Add("Take ownership");
        if (canRead && (canonical & FileExecute) != 0 && layer != PermissionLayer.Share)
            parts.Add("Read & Execute");
        else if (canRead)
            parts.Add("Read");
        else if ((canonical & FileExecute) != 0)
            parts.Add("Execute");

        if (parts.Count == 0)
            parts.Add("Special");

        return Make(string.Join(", ", parts), full: false, change: false, write: writeCapable, read: canRead, special: true);
    }

    private static RightsSummary Make(string text, bool full, bool change, bool write, bool read, bool special) =>
        new(text, full, change, write, read, special);
}
