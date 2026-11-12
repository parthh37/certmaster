namespace CertMaster.Models;

/// <summary>A step in a request or test, possibly with nested sub-steps.</summary>
public class ActionStep
{
    public ActionStep() { }
    public ActionStep(string title, string? description = null, bool hasError = false)
    { Title = title; Description = description; HasError = hasError; }

    public string Title { get; set; } = "";
    public string? Category { get; set; }
    public string? Description { get; set; }
    public bool HasError { get; set; }
    public bool HasWarning { get; set; }
    public List<ActionStep> Substeps { get; set; } = new();
}

public class ActionResult
{
    public ActionResult() { }
    public ActionResult(bool ok, string? message) { IsSuccess = ok; Message = message; }
    public bool IsSuccess { get; set; }
    public string? Message { get; set; }
    public List<ActionStep> Actions { get; set; } = new();

    public static ActionResult Ok(string? message = null) => new(true, message);
    public static ActionResult Fail(string message) => new(false, message);
}

public class ActionResult<T> : ActionResult
{
    public T? Result { get; set; }
}

public class CertificateRequestResult : ActionResult
{
    public ManagedCertificate? ManagedItem { get; set; }
}

/// <summary>Pushed over SignalR while a request is running.</summary>
public class RequestProgressState
{
    public string ManagedCertificateId { get; set; } = "";
    public string? InstanceId { get; set; }
    public RequestState CurrentState { get; set; }
    public string? Message { get; set; }
    public DateTimeOffset MessageCreated { get; set; } = DateTimeOffset.UtcNow;
    public string? Stage { get; set; }
    public bool IsFinal { get; set; }
}

public class LogEntry
{
    public DateTimeOffset Timestamp { get; set; }
    public string Level { get; set; } = "INF";
    public string Message { get; set; } = "";
}

public class SystemVersion
{
    public string Product { get; set; } = "CertMaster";
    public string Version { get; set; } = "";
    public string? OS { get; set; }
    public string? InstanceId { get; set; }
    public string? Hostname { get; set; }
}

public enum CertificateDownloadFormat { pfx, pem_full, pem_crt, pem_key, pem_chain }
