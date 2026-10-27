namespace ShareScope.Core;

public static class AppliesToFormatter
{
    public const int ContainerInherit = 1;
    public const int ObjectInherit = 2;
    public const int NoPropagateInherit = 1;
    public const int InheritOnly = 2;

    public static string Describe(int inheritanceFlags, int propagationFlags, PermissionLayer layer)
    {
        if (layer == PermissionLayer.Share)
            return "This share";

        var containers = (inheritanceFlags & ContainerInherit) != 0;
        var objects = (inheritanceFlags & ObjectInherit) != 0;
        var inheritOnly = (propagationFlags & InheritOnly) != 0;
        var noPropagate = (propagationFlags & NoPropagateInherit) != 0;

        string scope;
        if (!containers && !objects)
            scope = "This folder only";
        else if (inheritOnly && containers && objects)
            scope = "Subfolders and files only";
        else if (inheritOnly && containers)
            scope = "Subfolders only";
        else if (inheritOnly && objects)
            scope = "Files only";
        else if (containers && objects)
            scope = "This folder, subfolders and files";
        else if (containers)
            scope = "This folder and subfolders";
        else
            scope = "This folder and files";

        if (noPropagate && !inheritOnly)
            scope += " (one level)";

        return scope;
    }
}
